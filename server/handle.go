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

// sendEthernetFn is swappable so the layer-2 reply path can be exercised in
// tests without a raw socket.
var sendEthernetFn = sendEthernet

// errNoLayer2Interface is what the observer is told when a raw frame has
// nowhere to go. There is no error from the network stack to pass on here:
// the server never found out which interface the request arrived on.
var errNoLayer2Interface = errors.New("no interface information for a layer-2 reply; bind the DHCPv4 listener to an interface, for example `listen: \"%eth0\"`")

// ifaceName is the interface a packet arrived on: the one the listener is
// bound to, or the one the socket reported for this packet.
func (l *listener6) ifaceName(oobIdx int) string {
	if l.Index != 0 {
		return l.Name
	}
	return l.ifaces.name(oobIdx)
}

// ifaceName is the interface a packet arrived on: the one the listener is
// bound to, or the one the socket reported for this packet.
func (l *listener4) ifaceName(oobIdx int) string {
	if l.Index != 0 {
		return l.Name
	}
	return l.ifaces.name(oobIdx)
}

// infoAddrPort converts a socket address for handler.RequestInfo. Unlike
// peerAddrPort, which feeds the events an operator reads, this drops the IPv6
// zone: a plugin comparing a link-local peer against a configured address, or
// keying a rate limiter on it, wants fe80::1 rather than fe80::1%eth0, and
// the interface travels in its own field. A local address that is not UDP
// comes back as the zero value; only a test double produces one.
func infoAddrPort(a net.Addr) netip.AddrPort {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := peerAddrPort(ua)
	return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port())
}

// requestContext is what the DHCPv6 plugin chain is called with: a context
// carrying the request's handler.RequestInfo, or a background one when no
// plugin in the chain reads it. Filling the RequestInfo costs an interface
// lookup and a couple of allocations per packet, so a chain of plain handlers
// does not pay for it.
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

// requestContext is the DHCPv4 counterpart.
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

// relayDropped reports whether this request came through a relay while
// nothing in the chain vets relays, and counts the drop when it did.
//
// A DHCPv4 reply goes to giaddr and the sender picks giaddr, so with no
// allow list any host that can reach the server makes it reply to any
// address it names. The relay plugin holds that list; without it in the
// chain the server answers no relay at all.
func (l *listener4) relayDropped(req *dhcpv4.DHCPv4) bool {
	if l.relayChecked || !isRelayed4(req) {
		return false
	}
	l.gate.dropped(reasonRelayed)
	return true
}

// relayDropped is the DHCPv6 half. There is no giaddr: a relay wraps the
// client's message in a Relay-forward, so being relayed at all is what this
// refuses while no plugin says which relays are legitimate.
func (l *listener6) relayDropped(req dhcpv6.DHCPv6) bool {
	if l.relayChecked || !req.IsRelay() {
		return false
	}
	l.gate.dropped(reasonRelayed)
	return true
}

// startReport begins the event for one packet, or returns nil when no
// observer is attached. Everything it would cost, the clock read and the
// interface lookup included, sits behind that check.
func (l *listener6) startReport(oob *ipv6.ControlMessage, peer *net.UDPAddr) *requestReport {
	if l.observer == nil {
		return nil
	}
	return newReport(l.observer, events.FamilyV6, l.ifaceName(oobIfIndex6(oob)), peer)
}

// startReport begins the event for one packet, or returns nil when no
// observer is attached.
func (l *listener4) startReport(oob *ipv4.ControlMessage, peer *net.UDPAddr) *requestReport {
	if l.observer == nil {
		return nil
	}
	return newReport(l.observer, events.FamilyV4, l.ifaceName(oobIfIndex4(oob)), peer)
}

// HandleMsg6 runs for every received DHCPv6 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
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
	if l.relayDropped(req) {
		rep.emit(events.OutcomeDropped, events.PathNone, errRelayedNotAllowed)
		return
	}

	resp, err := buildReply6(req)
	if err != nil {
		log.Warningf("DHCPv6: cannot build a reply for the request from %v: %v; the packet is dropped, check the client or the relay if this repeats", peer, err)
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
		log.Warningf("DHCPv6: cannot create relay-repl from relay-forw: %v; the packet is dropped, check the relay agent if this repeats", err)
		rep.emit(events.OutcomeUnsupported, events.PathNone, err)
		return
	}
	rep.reply6(resp)

	var woob *ipv6.ControlMessage
	if peer.IP.IsLinkLocalUnicast() {
		// LL need to be directed to the correct interface. Globally reachable
		// addresses should use the default route, in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex6(oob)); idx != 0 {
			woob = &ipv6.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("DHCPv6: no interface for the link-local reply to %v, leaving the choice to the routing table; name the interface in `listen` if the reply goes astray", peer)
		}
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Printf("MainHandler6: conn.Write to %v failed: %v", peer, err)
		rep.emit(events.OutcomeSendError, events.PathUnicast, err)
		return
	}
	rep.emit(events.OutcomeReplied, events.PathUnicast, nil)
}

// HandleMsg4 runs for every received DHCPv4 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
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
	if l.relayDropped(req) {
		rep.emit(events.OutcomeDropped, events.PathNone, errRelayedNotAllowed)
		return
	}

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
		// The chain has had its say; whatever it built goes nowhere. This
		// check sits before the nil test on purpose: a RELEASE a plugin
		// stopped is not a drop, it is a message that was never going to
		// be answered. Before this existed, a RELEASE that survived the
		// chain left the server as a reply carrying no option 53 at all.
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
		// Direct broadcasts, link-local and layer2 unicasts to the interface
		// the request was received on. Other packets should use the normal
		// routing table in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex4(oob)); idx != 0 {
			woob = &ipv4.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("DHCPv4: no interface for the reply to %v, leaving the choice to the routing table; name the interface in `listen` if the reply goes astray", peer)
		}
	}

	if useEthernet {
		sendLayer2(rep, woob, resp)
		return
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Errorf("DHCPv4: writing the reply to %v failed: %v; the client gets nothing and will retry, check the route to it and the interface the socket is bound to", peer, err)
		rep.emit4(events.OutcomeSendError, peer, err)
		return
	}
	rep.emit4(events.OutcomeReplied, peer, nil)
}

// sendLayer2 puts a DHCPv4 reply on the wire as a raw frame, for a client
// that has no address to receive a datagram on yet.
func sendLayer2(rep *requestReport, woob *ipv4.ControlMessage, resp *dhcpv4.DHCPv4) {
	if woob == nil {
		// Without an interface there is nothing to put the frame on;
		// dereferencing woob here used to crash the server.
		log.Errorf("DHCPv4: cannot send layer-2 reply without interface information; bind the listener to an interface, for example `listen: \"%%eth0\"`")
		rep.emit(events.OutcomeSendError, events.PathLayer2, errNoLayer2Interface)
		return
	}
	intf, err := net.InterfaceByIndex(woob.IfIndex)
	if err != nil {
		log.Errorf("DHCPv4: interface index %d no longer names an interface: %v; the reply is dropped, this is what a link going down under the running server looks like", woob.IfIndex, err)
		rep.emit(events.OutcomeSendError, events.PathLayer2, err)
		return
	}
	if err := sendEthernetFn(*intf, resp); err != nil {
		log.Errorf("DHCPv4: cannot send the raw layer-2 reply: %v; the client gets nothing and will retry, check that the server has CAP_NET_RAW", err)
		rep.emit(events.OutcomeSendError, events.PathLayer2, err)
		return
	}
	rep.emit(events.OutcomeReplied, events.PathLayer2, nil)
}

// XXX: performance-wise, Pool may or may not be good (see https://github.com/golang/go/issues/23199)
// Interface is good for what we want. Maybe "just" trust the GC and we'll be fine ?
var bufpool = sync.Pool{New: func() any { r := make([]byte, MaxDatagram); return &r }}

// MaxDatagram is the maximum length of message that can be received.
const MaxDatagram = 1 << 16

// XXX: investigate using RecvMsgs to batch messages and reduce syscalls

// serve is the shared read loop: hand each datagram to handle on its own
// goroutine, bounded by the gate, until the connection closes.
func serve[M any](localAddr net.Addr, g *gate, readFrom func([]byte) (int, M, net.Addr, error), handle func([]byte, M, *net.UDPAddr)) error {
	log.Printf("Listen %s", localAddr)
	for {
		b := *bufpool.Get().(*[]byte) //nolint:forcetypeassert // bufpool only ever holds *[]byte
		b = b[:MaxDatagram]           // Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := readFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		datagram := b[:n]
		src, ok := peer.(*net.UDPAddr)
		if !ok {
			// readFrom is injected, so the peer is whatever the socket
			// underneath it reports. Anything without a port to answer on is
			// dropped rather than taking the read loop down with it.
			log.Printf("Received datagram from a peer that is not a *net.UDPAddr (%T), dropping", peer)
			bufpool.Put(&b)
			continue
		}
		if !g.run(func() { handle(datagram, oob, src) }) {
			// No handler ran, so nobody will hand the buffer back.
			bufpool.Put(&b)
		}
	}
}

// gateFor is the listener's gate, or a fresh default one for a listener
// built outside Start, which has none.
//
// It is deliberately not written back onto the listener: the handler
// goroutines read that field while they run, so assigning it here would be
// a race.
func gateFor(g *gate) *gate {
	if g == nil {
		return newGate(0)
	}
	return g
}

// Serve handles datagrams received on the DHCPv6 connection and passes them
// to the plugin chain.
func (l *listener6) Serve() error {
	return serve(l.LocalAddr(), gateFor(l.gate), l.ReadFrom, l.HandleMsg6)
}

// Serve handles datagrams received on the DHCPv4 connection and passes them
// to the plugin chain.
func (l *listener4) Serve() error {
	return serve(l.LocalAddr(), gateFor(l.gate), l.ReadFrom, l.HandleMsg4)
}
