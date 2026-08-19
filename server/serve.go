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

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
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
	handlers []handler.Handler6
}

type listener4 struct {
	conn4
	net.Interface
	handlers []handler.Handler4
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
func Start(config *config.Config) (*Servers, error) {
	handlers4, handlers6, err := plugins.LoadPlugins(config)
	if err != nil {
		return nil, err
	}
	srv := Servers{
		errors: make(chan error),
	}

	// listen
	if config.Server6 != nil {
		log.Println("Starting DHCPv6 server")
		for _, addr := range config.Server6.Addresses {
			var l6 *listener6
			l6, err = listen6(&addr)
			if err != nil {
				goto cleanup
			}
			l6.handlers = handlers6
			srv.listeners = append(srv.listeners, l6)
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
			l4.handlers = handlers4
			srv.listeners = append(srv.listeners, l4)
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
