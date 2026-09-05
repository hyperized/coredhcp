// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/handler"
)

// Swappable so the layer-2 reply path can be tested without a raw socket.
var sendEthernetFn = sendEthernet

// There is no network-stack error to pass on: the server never learned which
// interface the request arrived on.
var errNoLayer2Interface = errors.New("no interface information for a layer-2 reply")

func (l *listener6) ifaceName(oobIdx int) string {
	if l.Index != 0 {
		return l.Name
	}
	return l.ifaces.name(oobIdx)
}

func (l *listener4) ifaceName(oobIdx int) string {
	if l.Index != 0 {
		return l.Name
	}
	return l.ifaces.name(oobIdx)
}

// Drops the IPv6 zone that peerAddrPort keeps: a plugin matching a link-local
// peer against a configured address wants fe80::1, not fe80::1%eth0.
func infoAddrPort(a net.Addr) netip.AddrPort {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := peerAddrPort(ua)
	return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port())
}

// The RequestInfo is only filled when a plugin asks for it: it costs an
// interface lookup and allocations on every packet.
func (l *listener6) requestContext(oob *ipv6.ControlMessage, peer *net.UDPAddr) context.Context {
	if !l.wantsCtx {
		return context.Background()
	}
	idx := oobIfIndex6(oob)
	return handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Interface: l.ifaceName(idx),
		IfIndex:   replyIfIndex(l.Index, idx),
		Peer:      infoAddrPort(peer),
		Local:     infoAddrPort(l.LocalAddr()),
	})
}

func (l *listener4) requestContext(oob *ipv4.ControlMessage, src *net.UDPAddr) context.Context {
	if !l.wantsCtx {
		return context.Background()
	}
	idx := oobIfIndex4(oob)
	return handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Interface: l.ifaceName(idx),
		IfIndex:   replyIfIndex(l.Index, idx),
		Peer:      infoAddrPort(src),
		Local:     infoAddrPort(l.LocalAddr()),
	})
}

// Nil when nobody is watching, so the clock read and the interface lookup
// stay behind that check.
func (l *listener6) startReport(oob *ipv6.ControlMessage, peer *net.UDPAddr) *requestReport {
	if l.observer == nil {
		return nil
	}
	return newReport(l.observer, events.FamilyV6, l.ifaceName(oobIfIndex6(oob)), peer)
}

func (l *listener4) startReport(oob *ipv4.ControlMessage, peer *net.UDPAddr) *requestReport {
	if l.observer == nil {
		return nil
	}
	return newReport(l.observer, events.FamilyV4, l.ifaceName(oobIfIndex4(oob)), peer)
}

// HandleMsg6 runs the chain for one DHCPv6 packet. A nil response sends nothing.
func (l *listener6) HandleMsg6(buf []byte, oob *ipv6.ControlMessage, peer *net.UDPAddr) {
	rep := l.startReport(oob, peer)

	req, err := dhcpv6.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv6 request: %v", err)
		rep.emit(events.OutcomeParseError, events.PathNone, err)
		return
	}
	rep.request6(req)

	resp, err := buildReply6(req)
	if err != nil {
		log.Warningf("MainHandler6: %v", err)
		rep.emit(events.OutcomeUnsupported, events.PathNone, err)
		return
	}

	rep.chainStart()
	resp, stoppedAt := applyHandlers6(l.requestContext(oob, peer), l.chain, req, resp)
	rep.chainDone6(l.chain, stoppedAt)
	if resp == nil {
		log.Print("MainHandler6: dropping request because response is nil")
		rep.emit(events.OutcomeDropped, events.PathNone, nil)
		return
	}

	resp, err = encapsulateRelay6(req, resp)
	if err != nil {
		log.Warningf("DHCPv6: cannot create relay-repl from relay-forw: %v", err)
		rep.emit(events.OutcomeUnsupported, events.PathNone, err)
		return
	}
	rep.reply6(resp)

	var woob *ipv6.ControlMessage
	if peer.IP.IsLinkLocalUnicast() {
		// Link-local has to name the interface; a global address uses the
		// routing table, which is what asymmetric routing needs.
		if idx := replyIfIndex(l.Index, oobIfIndex6(oob)); idx != 0 {
			woob = &ipv6.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg6: Did not receive interface information")
		}
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Printf("MainHandler6: conn.Write to %v failed: %v", peer, err)
		rep.emit(events.OutcomeSendError, events.PathUnicast, err)
		return
	}
	rep.emit(events.OutcomeReplied, events.PathUnicast, nil)
}

// HandleMsg4 runs the chain for one DHCPv4 packet. A nil response sends nothing.
func (l *listener4) HandleMsg4(buf []byte, oob *ipv4.ControlMessage, src *net.UDPAddr) {
	rep := l.startReport(oob, src)

	req, err := dhcpv4.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv4 request: %v", err)
		rep.emit(events.OutcomeParseError, events.PathNone, err)
		return
	}
	rep.request4(req)

	resp, err := buildReply4(req)
	if err != nil {
		log.Printf("MainHandler4: %v", err)
		rep.emit(events.OutcomeUnsupported, events.PathNone, err)
		return
	}

	rep.chainStart()
	resp, stoppedAt := applyHandlers4(l.requestContext(oob, src), l.chain, req, resp)
	rep.chainDone4(l.chain, stoppedAt)
	if takesNoReply4(req.MessageType()) {
		// Ahead of the nil test on purpose: a RELEASE a plugin stopped is not a
		// drop, it was never going to be answered.
		log.Debugf("MainHandler4: %s takes no reply, sending nothing", req.MessageType())
		rep.emit(events.OutcomeNoReply, events.PathNone, nil)
		return
	}
	if resp == nil {
		log.Print("MainHandler4: dropping request because response is nil")
		rep.emit(events.OutcomeDropped, events.PathNone, nil)
		return
	}
	rep.reply4(resp)

	peer, useEthernet := replyDestination4(req, resp, src)

	var woob *ipv4.ControlMessage
	if peer.IP.Equal(net.IPv4bcast) || peer.IP.IsLinkLocalUnicast() || useEthernet {
		// Broadcast, link-local and layer-2 name the arrival interface; the
		// rest use the routing table, which is what asymmetric routing needs.
		if idx := replyIfIndex(l.Index, oobIfIndex4(oob)); idx != 0 {
			woob = &ipv4.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg4: Did not receive interface information")
		}
	}

	if useEthernet {
		sendLayer2(rep, woob, resp)
		return
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Errorf("MainHandler4: conn.Write to %v failed: %v", peer, err)
		rep.emit4(events.OutcomeSendError, peer, err)
		return
	}
	rep.emit4(events.OutcomeReplied, peer, nil)
}

// sendLayer2 sends a raw frame, for a client with no address to receive on.
func sendLayer2(rep *requestReport, woob *ipv4.ControlMessage, resp *dhcpv4.DHCPv4) {
	if woob == nil {
		log.Errorf("MainHandler4: cannot send layer-2 reply without interface information")
		rep.emit(events.OutcomeSendError, events.PathLayer2, errNoLayer2Interface)
		return
	}
	intf, err := net.InterfaceByIndex(woob.IfIndex)
	if err != nil {
		log.Errorf("MainHandler4: Can not get Interface for index %d %v", woob.IfIndex, err)
		rep.emit(events.OutcomeSendError, events.PathLayer2, err)
		return
	}
	if err := sendEthernetFn(*intf, resp); err != nil {
		log.Errorf("MainHandler4: Cannot send Ethernet packet: %v", err)
		rep.emit(events.OutcomeSendError, events.PathLayer2, err)
		return
	}
	rep.emit(events.OutcomeReplied, events.PathLayer2, nil)
}

// XXX: Pool may not pay for itself here, see golang/go#23199.
var bufpool = sync.Pool{New: func() any { r := make([]byte, MaxDatagram); return &r }}

// MaxDatagram is the maximum length of message that can be received.
const MaxDatagram = 1 << 16

// XXX: investigate using RecvMsgs to batch messages and reduce syscalls

// serve hands each datagram to handle on its own goroutine until the socket closes.
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

// Serve reads DHCPv6 datagrams until the socket closes.
func (l *listener6) Serve() error {
	return serve(l.LocalAddr(), l.ReadFrom, l.HandleMsg6)
}

// Serve reads DHCPv4 datagrams until the socket closes.
func (l *listener4) Serve() error {
	return serve(l.LocalAddr(), l.ReadFrom, l.HandleMsg4)
}
