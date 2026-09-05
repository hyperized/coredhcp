// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"context"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/handler"
)

// discardConn4 is a conn4 double whose WriteTo drops replies, so a
// benchmark measures HandleMsg4's own cost, not fakeConn4's bookkeeping.
type discardConn4 struct{}

func (discardConn4) ReadFrom([]byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	return 0, nil, nil, nil
}
func (discardConn4) WriteTo([]byte, *ipv4.ControlMessage, net.Addr) (int, error) { return 0, nil }
func (discardConn4) LocalAddr() net.Addr                                         { return &net.UDPAddr{} }
func (discardConn4) Close() error                                                { return nil }

type discardConn6 struct{}

func (discardConn6) ReadFrom([]byte) (int, *ipv6.ControlMessage, net.Addr, error) {
	return 0, nil, nil, nil
}
func (discardConn6) WriteTo([]byte, *ipv6.ControlMessage, net.Addr) (int, error) { return 0, nil }
func (discardConn6) LocalAddr() net.Addr                                         { return &net.UDPAddr{} }
func (discardConn6) Close() error                                                { return nil }

// passthrough4 is a one-plugin chain that hands the response through
// unchanged, giving HandleMsg4 the shortest realistic plugin path.
func passthrough4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }

func passthrough6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }

// BenchmarkHandleMsg4Discover measures full dispatch including the bufpool
// round trip HandleMsg4 does every packet, the same way Serve() does.
func BenchmarkHandleMsg4Discover(b *testing.B) {
	b.ReportAllocs()

	req, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		b.Fatal(err)
	}
	req.SetBroadcast()
	data := req.ToBytes()

	l := &listener4{conn4: discardConn4{}, chain: chain4(passthrough4)}
	l.Index = 1 // bound interface: avoids the "no interface information" error log on every broadcast reply
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}

	for b.Loop() {
		buf := *bufpool.Get().(*[]byte)
		buf = buf[:MaxDatagram]
		n := copy(buf, data)
		l.HandleMsg4(buf[:n], nil, peer)
	}
}

// passthroughCtx4 reads RequestInfo, so the benchmark pays for building one
// instead of measuring a handler that would just ignore it.
func passthroughCtx4(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if info, ok := handler.RequestInfoFrom(ctx); ok {
		_ = info.Interface
	}
	return resp, false
}

// BenchmarkHandleMsg4DiscoverWithContext isolates the RequestInfo cost the
// legacy benchmark above doesn't pay, by setting wantsCtx.
func BenchmarkHandleMsg4DiscoverWithContext(b *testing.B) {
	b.ReportAllocs()

	req, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		b.Fatal(err)
	}
	req.SetBroadcast()
	data := req.ToBytes()

	l := &listener4{conn4: discardConn4{}, chain: ctxChain4(passthroughCtx4), wantsCtx: true}
	// Bound interface, as above, and named: an unnamed one would leave
	// RequestInfo.Interface empty, which no real listener does.
	l.Index, l.Name = 1, "eth0"
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}

	for b.Loop() {
		buf := *bufpool.Get().(*[]byte)
		buf = buf[:MaxDatagram]
		n := copy(buf, data)
		l.HandleMsg4(buf[:n], nil, peer)
	}
}

func BenchmarkHandleMsg6Solicit(b *testing.B) {
	b.ReportAllocs()

	req, err := dhcpv6.NewSolicit(testMAC)
	if err != nil {
		b.Fatal(err)
	}
	data := req.ToBytes()

	l := &listener6{conn6: discardConn6{}, chain: chain6(passthrough6)}
	peer := &net.UDPAddr{IP: net.ParseIP("2001:db8::1")}

	for b.Loop() {
		buf := *bufpool.Get().(*[]byte)
		buf = buf[:MaxDatagram]
		n := copy(buf, data)
		l.HandleMsg6(buf[:n], nil, peer)
	}
}

// BenchmarkBuildReply4 isolates buildReply4 from dispatch overhead.
func BenchmarkBuildReply4(b *testing.B) {
	b.ReportAllocs()

	req, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if _, err := buildReply4(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplyDestination4 isolates replyDestination4's routing decision
// on the gateway-set path, the cheapest and most common relayed case.
func BenchmarkReplyDestination4(b *testing.B) {
	b.ReportAllocs()

	req, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")))
	if err != nil {
		b.Fatal(err)
	}
	resp, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		replyDestination4(req, resp, nil)
	}
}
