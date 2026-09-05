// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
)

// ctxChain4 exists because chain4 wraps a plain handler.Handler4 and drops
// the context before the handler ever sees it.
func ctxChain4(handlers ...handler.Handler4Ctx) []plugins.Link4 {
	chain := make([]plugins.Link4, 0, len(handlers))
	for i, h := range handlers {
		chain = append(chain, plugins.Link4{Name: fmt.Sprintf("plugin%d", i+1), Handler: h, WantsContext: true})
	}
	return chain
}

func ctxChain6(handlers ...handler.Handler6Ctx) []plugins.Link6 {
	chain := make([]plugins.Link6, 0, len(handlers))
	for i, h := range handlers {
		chain = append(chain, plugins.Link6{Name: fmt.Sprintf("plugin%d", i+1), Handler: h, WantsContext: true})
	}
	return chain
}

// A bound listener is authoritative about its interface: whatever the
// handler sees must match l.Index/l.Name, not any control message claim.
func TestRequestContextBoundListener(t *testing.T) {
	t.Run("dhcpv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast() // keep the reply off the layer-2 path so HandleMsg4 runs to completion

		var got handler.RequestInfo
		var ok bool
		record := func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			got, ok = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		conn := &fakeConn4{local: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 67}}
		l := &listener4{conn4: conn, chain: ctxChain4(record), wantsCtx: true}
		l.Index, l.Name = 7, "eth1"

		l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 68})

		require.True(t, ok)
		assert.Equal(t, "eth1", got.Interface)
		assert.Equal(t, 7, got.IfIndex)
		assert.Equal(t, netip.MustParseAddrPort("192.0.2.5:68"), got.Peer)
		assert.Equal(t, netip.MustParseAddrPort("203.0.113.9:67"), got.Local)
	})

	t.Run("dhcpv6", func(t *testing.T) {
		req := mustSolicit(t, false)

		var got handler.RequestInfo
		var ok bool
		record := func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			got, ok = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		conn := &fakeConn6{local: &net.UDPAddr{IP: net.ParseIP("2001:db8::9"), Port: 547}}
		l := &listener6{conn6: conn, chain: ctxChain6(record), wantsCtx: true}
		l.Index, l.Name = 7, "eth1"

		l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 546})

		require.True(t, ok)
		assert.Equal(t, "eth1", got.Interface)
		assert.Equal(t, 7, got.IfIndex)
		assert.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:546"), got.Peer)
		assert.Equal(t, netip.MustParseAddrPort("[2001:db8::9]:547"), got.Local)
	})
}

// An unbound listener resolves the interface per packet from the control
// message index, through its ifaceCache.
func TestRequestContextUnboundListenerResolvesOobIndex(t *testing.T) {
	loName := loopbackInterfaceName(t)
	lo, err := net.InterfaceByName(loName)
	require.NoError(t, err)

	t.Run("dhcpv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast()

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		l := &listener4{conn4: &fakeConn4{}, chain: ctxChain4(record), wantsCtx: true}
		l.HandleMsg4(datagramBuf(req.ToBytes()), &ipv4.ControlMessage{IfIndex: lo.Index}, &net.UDPAddr{IP: net.ParseIP("192.0.2.5")})

		assert.Equal(t, loName, got.Interface)
		assert.Equal(t, lo.Index, got.IfIndex)
	})

	t.Run("dhcpv6", func(t *testing.T) {
		req := mustMessage6(t, dhcpv6.MessageTypeRequest)

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		l := &listener6{conn6: &fakeConn6{}, chain: ctxChain6(record), wantsCtx: true}
		l.HandleMsg6(datagramBuf(req.ToBytes()), &ipv6.ControlMessage{IfIndex: lo.Index}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

		assert.Equal(t, loName, got.Interface)
		assert.Equal(t, lo.Index, got.IfIndex)
	})
}

// An unresolvable index still reaches the plugin as a bare number: only the
// name lookup fails, the request is not dropped for it.
func TestRequestContextUnresolvableOobIndex(t *testing.T) {
	t.Run("dhcpv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast()

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		conn := &fakeConn4{}
		l := &listener4{conn4: conn, chain: ctxChain4(record), wantsCtx: true}
		l.HandleMsg4(datagramBuf(req.ToBytes()), &ipv4.ControlMessage{IfIndex: 999999}, &net.UDPAddr{IP: net.ParseIP("192.0.2.5")})

		assert.Empty(t, got.Interface)
		assert.Equal(t, 999999, got.IfIndex)
		assert.Len(t, conn.writes, 1)
	})

	t.Run("dhcpv6", func(t *testing.T) {
		req := mustMessage6(t, dhcpv6.MessageTypeRequest)

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		conn := &fakeConn6{}
		l := &listener6{conn6: conn, chain: ctxChain6(record), wantsCtx: true}
		l.HandleMsg6(datagramBuf(req.ToBytes()), &ipv6.ControlMessage{IfIndex: 999999}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

		assert.Empty(t, got.Interface)
		assert.Equal(t, 999999, got.IfIndex)
		assert.Len(t, conn.writes, 1)
	})
}

// A legacy (non-context) chain works unchanged; requestContext's effect on
// it can't be observed via Handler4/6, so the context itself is checked directly.
func TestRequestContextLegacyChain(t *testing.T) {
	t.Run("dhcpv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast()
		pass := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }

		conn := &fakeConn4{}
		l := newTestListener4([]handler.Handler4{pass}, conn) // wantsCtx left at its zero value, false
		l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.5")})
		require.Len(t, conn.writes, 1)

		ctx := l.requestContext(nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.5")})
		require.NotNil(t, ctx)
		_, ok := handler.RequestInfoFrom(ctx)
		assert.False(t, ok)
	})

	t.Run("dhcpv6", func(t *testing.T) {
		req := mustMessage6(t, dhcpv6.MessageTypeRequest)
		pass := func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }

		conn := &fakeConn6{}
		l := newTestListener6([]handler.Handler6{pass}, conn)
		l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
		require.Len(t, conn.writes, 1)

		ctx := l.requestContext(nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
		require.NotNil(t, ctx)
		_, ok := handler.RequestInfoFrom(ctx)
		assert.False(t, ok)
	})
}

// Interface carries interface identity because a peer's zone differs by
// interface; 4-in-6 unmapping shares this test since it's the same code path.
func TestRequestContextZoneAndMappedAddresses(t *testing.T) {
	t.Run("dhcpv6 link-local peer loses its zone", func(t *testing.T) {
		req := mustMessage6(t, dhcpv6.MessageTypeRequest)

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		conn := &fakeConn6{}
		l := &listener6{conn6: conn, chain: ctxChain6(record), wantsCtx: true}
		l.Index, l.Name = 3, "eth0" // bound, so the link-local reply has an interface to leave on and logs nothing

		l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 546, Zone: "eth0"})

		assert.Equal(t, "eth0", got.Interface)
		assert.Equal(t, "fe80::1", got.Peer.Addr().String())
		assert.Empty(t, got.Peer.Addr().Zone())
		require.Len(t, conn.writes, 1)
	})

	t.Run("dhcpv4 4-in-6 source becomes plain IPv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast()

		var got handler.RequestInfo
		record := func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			got, _ = handler.RequestInfoFrom(ctx)
			return resp, false
		}

		l := &listener4{conn4: &fakeConn4{}, chain: ctxChain4(record), wantsCtx: true}
		l.Index = 1

		l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 68})

		assert.True(t, got.Peer.Addr().Is4())
		assert.Equal(t, "192.0.2.7:68", got.Peer.String())
	})
}

// The nil-UDP case is a typed nil: *net.UDPAddr is still the dynamic type,
// so infoAddrPort must not just check for a nil interface.
func TestInfoAddrPort(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
	}{
		{name: "non-UDP address", addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}},
		{name: "nil UDP address", addr: (*net.UDPAddr)(nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, netip.AddrPort{}, infoAddrPort(tc.addr))
		})
	}
}

// No real conn4/conn6 has a non-UDP LocalAddr; this proves Local degrades to
// the zero value instead of assuming the type, while Peer is unaffected.
func TestRequestContextNonUDPLocalAddr(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast()

	var got handler.RequestInfo
	record := func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		got, _ = handler.RequestInfoFrom(ctx)
		return resp, false
	}

	conn := &fakeConn4{local: &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 67}}
	l := &listener4{conn4: conn, chain: ctxChain4(record), wantsCtx: true}
	l.Index = 1

	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 68})

	assert.Equal(t, netip.AddrPort{}, got.Local)
	assert.Equal(t, netip.MustParseAddrPort("192.0.2.5:68"), got.Peer)
}

// The stop/drop contract applyHandlers4/6 honour for plain chains holds for
// context-aware ones too: this proves it rather than assuming it.
func TestContextAwareChainStopAndDrop(t *testing.T) {
	t.Run("dhcpv4", func(t *testing.T) {
		req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
		req.SetBroadcast()

		var order []int
		first := func(_ context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 1)
			return resp, false
		}
		second := func(_ context.Context, _, _ *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 2)
			return nil, true
		}
		third := func(_ context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 3)
			return resp, false
		}

		conn := &fakeConn4{}
		l := &listener4{conn4: conn, chain: ctxChain4(first, second, third), wantsCtx: true}
		l.Index = 1

		l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.5")})

		assert.Equal(t, []int{1, 2}, order)
		assert.Empty(t, conn.writes)
	})

	t.Run("dhcpv6", func(t *testing.T) {
		req := mustSolicit(t, false)

		var order []int
		first := func(_ context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 1)
			return resp, false
		}
		second := func(_ context.Context, _, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 2)
			return nil, true
		}
		third := func(_ context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 3)
			return resp, false
		}

		conn := &fakeConn6{}
		l := &listener6{conn6: conn, chain: ctxChain6(first, second, third), wantsCtx: true}

		l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

		assert.Equal(t, []int{1, 2}, order)
		assert.Empty(t, conn.writes)
	})
}
