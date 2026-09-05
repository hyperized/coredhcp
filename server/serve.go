// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package server listens for DHCPv4 and DHCPv6 packets and dispatches
// them through the configured plugin handler chains.
package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("server")

// The subset of *ipv6.PacketConn the dispatch path uses, so a test needs no socket.
type conn6 interface {
	ReadFrom(b []byte) (int, *ipv6.ControlMessage, net.Addr, error)
	WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error)
	LocalAddr() net.Addr
	Close() error
}

// The subset of *ipv4.PacketConn the dispatch path uses, so a test needs no socket.
type conn4 interface {
	ReadFrom(b []byte) (int, *ipv4.ControlMessage, net.Addr, error)
	WriteTo(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error)
	LocalAddr() net.Addr
	Close() error
}

type listener6 struct {
	conn6
	net.Interface
	chain    []plugins.Link6
	observer events.Observer
	ifaces   ifaceCache
	// Answered once at startup: per packet it would mean walking the whole
	// chain before running any of it.
	wantsCtx bool
}

type listener4 struct {
	conn4
	net.Interface
	chain    []plugins.Link4
	observer events.Observer
	ifaces   ifaceCache
	wantsCtx bool
}

// ifaceCache maps interface indexes to names for one listener.
// net.InterfaceByIndex is a netlink dump on Linux, too expensive per packet, so
// an interface renamed under a running server keeps the name it was first seen with.
type ifaceCache struct {
	names sync.Map // int index -> string name
}

// A failed lookup is cached too, so a vanished interface is not retried per packet.
func (c *ifaceCache) name(idx int) string {
	if idx == 0 {
		return ""
	}
	if cached, ok := c.names.Load(idx); ok {
		return cached.(string)
	}
	var name string
	if ifi, err := net.InterfaceByIndex(idx); err == nil {
		name = ifi.Name
	}
	c.names.Store(idx, name)
	return name
}

// Swappable so socket-setup error paths are reachable without privileges. The
// net.PacketConn return, not the library's *net.UDPConn, is what lets a test
// substitute a socket whose Close it can observe.
var (
	newUDP4 = newIPv4UDPConn
	newUDP6 = newIPv6UDPConn
)

func newIPv4UDPConn(zone string, a *net.UDPAddr) (net.PacketConn, error) {
	// Returning the result directly would put a typed nil in the interface on
	// the error path, and a typed nil is not nil.
	c, err := server4.NewIPv4UDPConn(zone, a)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func newIPv6UDPConn(zone string, a *net.UDPAddr) (net.PacketConn, error) {
	c, err := server6.NewIPv6UDPConn(zone, a)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// listener is one bound socket: a read loop, and the Close that ends it.
type listener interface {
	io.Closer

	Serve() error
}

// `listen: []` binds nothing, and a server that binds nothing then sits in
// Wait looks alive from the outside, so it is refused up front.
var errNoListeners = errors.New("no listen addresses configured for DHCPv6 or DHCPv4")

// Servers contains state for a running server (with possibly multiple interfaces/listeners)
type Servers struct {
	listeners []listener
	errors    chan error
	observer  events.Observer
	// Counts started Serve goroutines, so a failed Start can join them.
	running sync.WaitGroup
}

// Option configures Start.
type Option func(*Servers)

// WithObserver reports every listener, plugin and handled datagram to o, which
// must be safe for concurrent use and must not block. See events.Observer.
func WithObserver(o events.Observer) Option {
	return func(s *Servers) { s.observer = o }
}

// Arguments go through config.RedactArgs first: an observer puts them on
// screen, and that list is where a Redis password or NetBox token is written.
func (s *Servers) reportPlugins(chains *plugins.Chains) {
	if s.observer == nil {
		return
	}
	for _, l := range chains.V6 {
		s.observer.Plugin(events.Plugin{Family: events.FamilyV6, Name: l.Name, Args: config.RedactArgs(l.Args)})
	}
	for _, l := range chains.V4 {
		s.observer.Plugin(events.Plugin{Family: events.FamilyV4, Name: l.Name, Args: config.RedactArgs(l.Args)})
	}
}

// zone is empty when the listener is not bound to an interface.
func (s *Servers) reportListener(family events.Family, addr net.Addr, zone string) {
	if s.observer == nil {
		return
	}
	s.observer.Listener(events.Listener{Family: family, Address: addr.String(), Interface: zone})
}

func listen4(a *net.UDPAddr) (*listener4, error) {
	l4 := listener4{}
	udpConn, err := newUDP4(a.Zone, a)
	if err != nil {
		return nil, err
	}
	// Nothing else holds this socket yet, so every error path below has to
	// close it. Disarmed once the caller takes ownership of the listener.
	handedOver := false
	defer func() {
		if !handedOver {
			_ = udpConn.Close()
		}
	}()
	pc := ipv4.NewPacketConn(udpConn)
	l4.conn4 = pc
	var ifi *net.Interface
	if a.Zone != "" {
		ifi, err = net.InterfaceByName(a.Zone)
		if err != nil {
			return nil, fmt.Errorf("DHCPv4: Listen could not find interface %s: %w", a.Zone, err)
		}
		l4.Interface = *ifi
	} else {
		// Unbound, so each packet has to say which interface it came in on.
		err = pc.SetControlMessage(ipv4.FlagInterface, true)
		if err != nil {
			return nil, err
		}
	}

	if a.IP.IsMulticast() {
		err = pc.JoinGroup(ifi, a)
		if err != nil {
			return nil, err
		}
	}
	handedOver = true
	return &l4, nil
}

func listen6(a *net.UDPAddr) (*listener6, error) {
	l6 := listener6{}
	udpconn, err := newUDP6(a.Zone, a)
	if err != nil {
		return nil, err
	}
	// See listen4.
	handedOver := false
	defer func() {
		if !handedOver {
			_ = udpconn.Close()
		}
	}()
	pc := ipv6.NewPacketConn(udpconn)
	l6.conn6 = pc
	var ifi *net.Interface
	if a.Zone != "" {
		ifi, err = net.InterfaceByName(a.Zone)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6: Listen could not find interface %s: %w", a.Zone, err)
		}
		l6.Interface = *ifi
	} else {
		// Unbound, so each packet has to say which interface it came in on.
		err = pc.SetControlMessage(ipv6.FlagInterface, true)
		if err != nil {
			return nil, err
		}
	}

	if a.IP.IsMulticast() {
		err = pc.JoinGroup(ifi, a)
		if err != nil {
			return nil, err
		}
	}
	handedOver = true
	return &l6, nil
}

// Sizes the errors channel, which needs one slot per Serve goroutine so that
// none of them can block on the send.
func countAddresses(c *config.Config) int {
	n := 0
	if c.Server6 != nil {
		n += len(c.Server6.Addresses)
	}
	if c.Server4 != nil {
		n += len(c.Server4.Addresses)
	}
	return n
}

// Start starts the server asynchronously; see Wait for the end of it. Binding
// is all or nothing, and a failed call leaves no socket or goroutine behind.
func Start(config *config.Config, opts ...Option) (*Servers, error) {
	chains, err := plugins.LoadChains(config)
	if err != nil {
		return nil, err
	}
	total := countAddresses(config)
	if total == 0 {
		return nil, errNoListeners
	}
	srv := Servers{
		// One slot per socket, so no Serve goroutine can block on the send
		// when a later bind fails and cleanup closes its socket.
		errors: make(chan error, total),
	}
	for _, opt := range opts {
		opt(&srv)
	}
	srv.reportPlugins(chains)

	if err := srv.start6(config, chains); err != nil {
		srv.shutdown()
		return nil, err
	}
	if err := srv.start4(config, chains); err != nil {
		srv.shutdown()
		return nil, err
	}
	return &srv, nil
}

// Stops at the first bind that fails; sockets opened before it stay in
// s.listeners for the caller to close.
func (s *Servers) start6(c *config.Config, chains *plugins.Chains) error {
	if c.Server6 == nil {
		return nil
	}
	log.Println("Starting DHCPv6 server")
	wantsCtx := plugins.WantsContext(chains.V6)
	for i := range c.Server6.Addresses {
		addr := c.Server6.Addresses[i]
		l6, err := listen6(&addr)
		if err != nil {
			return err
		}
		l6.chain = chains.V6
		l6.wantsCtx = wantsCtx
		l6.observer = s.observer
		s.listeners = append(s.listeners, l6)
		s.reportListener(events.FamilyV6, l6.LocalAddr(), addr.Zone)
		s.serve(l6)
	}
	return nil
}

func (s *Servers) start4(c *config.Config, chains *plugins.Chains) error {
	if c.Server4 == nil {
		return nil
	}
	log.Println("Starting DHCPv4 server")
	wantsCtx := plugins.WantsContext(chains.V4)
	for i := range c.Server4.Addresses {
		addr := c.Server4.Addresses[i]
		l4, err := listen4(&addr)
		if err != nil {
			return err
		}
		l4.chain = chains.V4
		l4.wantsCtx = wantsCtx
		l4.observer = s.observer
		s.listeners = append(s.listeners, l4)
		s.reportListener(events.FamilyV4, l4.LocalAddr(), addr.Zone)
		s.serve(l4)
	}
	return nil
}

func (s *Servers) serve(l listener) {
	s.running.Add(1)
	go func() {
		defer s.running.Done()
		s.errors <- l.Serve()
	}()
}

// Synchronous on purpose: a failed Start must not leave a read loop running
// after the caller has the error.
func (s *Servers) shutdown() {
	s.Close()
	s.running.Wait()
}

// Wait blocks until the server stops. It returns nil when every listener was
// closed on purpose, and the joined errors of the ones that failed otherwise.
func (s *Servers) Wait() error {
	log.Debug("Waiting")
	if len(s.listeners) == 0 {
		return nil
	}
	errs := make([]error, 0, len(s.listeners))
	// The first listener to stop takes the rest with it: a server missing one
	// socket is not serving the network it was configured for.
	errs = append(errs, <-s.errors)
	s.Close()
	for i := 1; i < len(s.listeners); i++ {
		errs = append(errs, <-s.errors)
	}
	return errors.Join(errs...)
}

// Close closes all listening connections. Safe to call more than once: a
// signal and Wait both close the listeners.
func (s *Servers) Close() {
	for _, srv := range s.listeners {
		if srv != nil {
			if err := srv.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Errorf("error closing listener: %v", err)
			}
		}
	}
}
