// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// rawUDP wraps the dhcp library's raw client socket.
//
// The wrapper exists for one reason: a DHCPRELEASE has to leave with the
// leased address in the IP header, because the relay plugin compares ciaddr
// against the datagram source. The library's conn writes whatever address it
// was constructed with, so a second wrapper over the same file descriptor is
// all a different source takes.
type rawUDP struct {
	net.PacketConn
	inner net.PacketConn
	port  int
}

// openRawUDP opens an AF_PACKET socket on ifname, reading datagrams
// addressed to port.
//
// It has to be raw. The server answers a client that holds no address with a
// layer 2 unicast to the hardware address in the request, and the exerciser
// makes those addresses up, so no ordinary socket in this container would
// ever see the reply.
func openRawUDP(ifname string, port int) (rawUDPConn, error) {
	pc, err := nclient4.NewRawUDPConn(ifname, port)
	if err != nil {
		return nil, fmt.Errorf("opening a raw socket on %s: %w; the container needs NET_RAW", ifname, err)
	}
	bc, ok := pc.(*nclient4.BroadcastRawUDPConn)
	if !ok {
		return &rawUDP{PacketConn: pc, inner: pc, port: port}, nil
	}
	return &rawUDP{PacketConn: bc, inner: bc.PacketConn, port: port}, nil
}

// withSource returns a conn over the same socket that writes src as the IP
// source address. Only write to it: two readers on one descriptor would take
// each other's datagrams.
func (r *rawUDP) withSource(src netip.Addr) net.PacketConn {
	return nclient4.NewBroadcastUDPConn(r.inner, &net.UDPAddr{IP: src.AsSlice(), Port: r.port})
}
