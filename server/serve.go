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

// conn6 is the subset of *ipv6.PacketConn the dispatch path uses, split out
// so it can be exercised without a real socket.
type conn6 interface {
	ReadFrom(b []byte) (int, *ipv6.ControlMessage, net.Addr, error)
	WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error)
	LocalAddr() net.Addr
	Close() error
}

// conn4 is the subset of *ipv4.PacketConn the dispatch path uses, split out
// so it can be exercised without a real socket.
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
}

type listener4 struct {
	conn4
	net.Interface
	chain    []plugins.Link4
	observer events.Observer
	ifaces   ifaceCache
}

// ifaceCache maps interface indexes to names for one listener.
//
// A listener that is not bound to an interface learns which one a packet came
// in on from the socket's control message, and that carries only the index.
// net.InterfaceByIndex is a netlink dump on Linux, far too expensive to run
// per packet, so the answer is kept for the life of the listener. An
// interface renamed while the server runs keeps the name it had when it was
// first seen: a stale label in the observer is a better trade than a syscall
// on the packet path, and interfaces are not renamed under a running DHCP
// server in practice.
//
// The cache is only ever consulted when an observer is attached.
type ifaceCache struct {
	names sync.Map // int index -> string name
}

// name resolves an interface index, empty for index 0 or an index that no
// longer exists. A failed lookup is remembered too, so a packet from a
// vanished interface does not retry the syscall on every datagram.
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

// The socket constructors are swappable so socket-setup error paths can be
// reached in tests without privileges.
var (
	newUDP4 = server4.NewIPv4UDPConn
	newUDP6 = server6.NewIPv6UDPConn
)

type listener interface {
	io.Closer
}

// Servers contains state for a running server (with possibly multiple interfaces/listeners)
type Servers struct {
	listeners []listener
	errors    chan error
	observer  events.Observer
}

// Option configures Start.
type Option func(*Servers)

// WithObserver reports what the server does to o: one events.Listener per
// socket it binds, one events.Plugin per plugin it loaded, and one
// events.Request for every datagram it handles, whatever became of it. o must
// be safe for concurrent use and must not block, see events.Observer.
//
// The default is no observer, which is what the server has always done and
// costs a nil check per packet.
func WithObserver(o events.Observer) Option {
	return func(s *Servers) { s.observer = o }
}

// reportPlugins names the plugins in each chain, in chain order, DHCPv6 first
// to match the order the listeners start in below. A plugin configured twice
// is reported twice, since it is two links in the chain.
func (s *Servers) reportPlugins(chains *plugins.Chains) {
	if s.observer == nil {
		return
	}
	for _, l := range chains.V6 {
		s.observer.Plugin(events.Plugin{Family: events.FamilyV6, Name: l.Name, Args: l.Args})
	}
	for _, l := range chains.V4 {
		s.observer.Plugin(events.Plugin{Family: events.FamilyV4, Name: l.Name, Args: l.Args})
	}
}

// reportListener announces a socket the server just bound. zone is the
// interface from the configured address, empty when the listener is not bound
// to one.
func (s *Servers) reportListener(family events.Family, addr net.Addr, zone string) {
	if s.observer == nil {
		return
	}
	s.observer.Listener(events.Listener{Family: family, Address: addr.String(), Interface: zone})
}

func listen4(a *net.UDPAddr) (*listener4, error) {
	var err error
	l4 := listener4{}
	udpConn, err := newUDP4(a.Zone, a)
	if err != nil {
		return nil, err
	}
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
		// When not bound to an interface, we need the information in each
		// packet to know which interface it came on
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
	return &l4, nil
}

func listen6(a *net.UDPAddr) (*listener6, error) {
	l6 := listener6{}
	udpconn, err := newUDP6(a.Zone, a)
	if err != nil {
		return nil, err
	}
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
		// When not bound to an interface, we need the information in each
		// packet to know which interface it came on
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
	return &l6, nil
}

// Start will start the server asynchronously. See `Wait` to wait until
// the execution ends.
func Start(config *config.Config, opts ...Option) (*Servers, error) {
	chains, err := plugins.LoadChains(config)
	if err != nil {
		return nil, err
	}
	srv := Servers{
		errors: make(chan error),
	}
	for _, opt := range opts {
		opt(&srv)
	}
	srv.reportPlugins(chains)

	// listen
	if config.Server6 != nil {
		log.Println("Starting DHCPv6 server")
		for _, addr := range config.Server6.Addresses {
			var l6 *listener6
			l6, err = listen6(&addr)
			if err != nil {
				goto cleanup
			}
			l6.chain = chains.V6
			l6.observer = srv.observer
			srv.listeners = append(srv.listeners, l6)
			srv.reportListener(events.FamilyV6, l6.LocalAddr(), addr.Zone)
			go func() {
				srv.errors <- l6.Serve()
			}()
		}
	}

	if config.Server4 != nil {
		log.Println("Starting DHCPv4 server")
		for _, addr := range config.Server4.Addresses {
			var l4 *listener4
			l4, err = listen4(&addr)
			if err != nil {
				goto cleanup
			}
			l4.chain = chains.V4
			l4.observer = srv.observer
			srv.listeners = append(srv.listeners, l4)
			srv.reportListener(events.FamilyV4, l4.LocalAddr(), addr.Zone)
			go func() {
				srv.errors <- l4.Serve()
			}()
		}
	}

	return &srv, nil

cleanup:
	srv.Close()
	return nil, err
}

// Wait waits until the end of the execution of the server.
func (s *Servers) Wait() error {
	log.Debug("Waiting")
	errs := make([]error, 1, len(s.listeners))
	errs[0] = <-s.errors
	s.Close()
	// Wait for the other listeners to close
	for i := 1; i < len(s.listeners); i++ {
		errs = append(errs, <-s.errors)
	}
	return errors.Join(errs...)
}

// Close closes all listening connections. It is safe to call more than once:
// a shutdown signal and Wait both close the listeners, and the second close
// of a connection is not an error worth reporting.
func (s *Servers) Close() {
	for _, srv := range s.listeners {
		if srv != nil {
			if err := srv.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Errorf("error closing listener: %v", err)
			}
		}
	}
}
