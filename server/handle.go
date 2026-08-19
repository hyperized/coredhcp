// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// sendEthernetFn is swappable so the layer-2 reply path can be exercised in
// tests without a raw socket.
var sendEthernetFn = sendEthernet

// HandleMsg6 runs for every received DHCPv6 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
func (l *listener6) HandleMsg6(buf []byte, oob *ipv6.ControlMessage, peer *net.UDPAddr) {
	req, err := dhcpv6.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv6 request: %v", err)
		return
	}

	resp, err := buildReply6(req)
	if err != nil {
		log.Warningf("MainHandler6: %v", err)
		return
	}

	resp = applyHandlers6(l.handlers, req, resp)
	if resp == nil {
		log.Print("MainHandler6: dropping request because response is nil")
		return
	}

	resp, err = encapsulateRelay6(req, resp)
	if err != nil {
		log.Warningf("DHCPv6: cannot create relay-repl from relay-forw: %v", err)
		return
	}

	var woob *ipv6.ControlMessage
	if peer.IP.IsLinkLocalUnicast() {
		// LL need to be directed to the correct interface. Globally reachable
		// addresses should use the default route, in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex6(oob)); idx != 0 {
			woob = &ipv6.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg6: Did not receive interface information")
		}
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Printf("MainHandler6: conn.Write to %v failed: %v", peer, err)
	}
}

// HandleMsg4 runs for every received DHCPv4 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
func (l *listener4) HandleMsg4(buf []byte, oob *ipv4.ControlMessage, src *net.UDPAddr) {
	req, err := dhcpv4.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv4 request: %v", err)
		return
	}

	resp, err := buildReply4(req)
	if err != nil {
		log.Printf("MainHandler4: %v", err)
		return
	}

	resp = applyHandlers4(l.handlers, req, resp)
	if resp == nil {
		log.Print("MainHandler4: dropping request because response is nil")
		return
	}

	peer, useEthernet := replyDestination4(req, resp, src)

	var woob *ipv4.ControlMessage
	if peer.IP.Equal(net.IPv4bcast) || peer.IP.IsLinkLocalUnicast() || useEthernet {
		// Direct broadcasts, link-local and layer2 unicasts to the interface
		// the request was received on. Other packets should use the normal
		// routing table in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex4(oob)); idx != 0 {
			woob = &ipv4.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg4: Did not receive interface information")
		}
	}

	if useEthernet {
		if woob == nil {
			// Without an interface there is nothing to put the frame on;
			// dereferencing woob here used to crash the server.
			log.Errorf("MainHandler4: cannot send layer-2 reply without interface information")
			return
		}
		intf, err := net.InterfaceByIndex(woob.IfIndex)
		if err != nil {
			log.Errorf("MainHandler4: Can not get Interface for index %d %v", woob.IfIndex, err)
			return
		}
		if err := sendEthernetFn(*intf, resp); err != nil {
			log.Errorf("MainHandler4: Cannot send Ethernet packet: %v", err)
		}
		return
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Errorf("MainHandler4: conn.Write to %v failed: %v", peer, err)
	}
}

// XXX: performance-wise, Pool may or may not be good (see https://github.com/golang/go/issues/23199)
// Interface is good for what we want. Maybe "just" trust the GC and we'll be fine ?
var bufpool = sync.Pool{New: func() any { r := make([]byte, MaxDatagram); return &r }}

// MaxDatagram is the maximum length of message that can be received.
const MaxDatagram = 1 << 16

// XXX: investigate using RecvMsgs to batch messages and reduce syscalls

// serve is the shared read loop: hand each datagram to handle on its own
// goroutine until the connection closes.
func serve[M any](localAddr net.Addr, readFrom func([]byte) (int, M, net.Addr, error), handle func([]byte, M, *net.UDPAddr)) error {
	log.Printf("Listen %s", localAddr)
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] // Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := readFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go handle(b[:n], oob, peer.(*net.UDPAddr))
	}
}

// Serve handles datagrams received on the DHCPv6 connection and passes them
// to the plugin chain.
func (l *listener6) Serve() error {
	return serve(l.LocalAddr(), l.ReadFrom, l.HandleMsg6)
}

// Serve handles datagrams received on the DHCPv4 connection and passes them
// to the plugin chain.
func (l *listener4) Serve() error {
	return serve(l.LocalAddr(), l.ReadFrom, l.HandleMsg4)
}
