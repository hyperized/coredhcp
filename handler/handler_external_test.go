// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package handler_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
)

// TestHandlerTypes is a compile-time and shape check that Handler4 and
// Handler6 accept and return the packet types every plugin relies on. The
// package declares only these two function types, so there is no other
// behaviour to exercise.
func TestHandlerTypes(t *testing.T) {
	var h4 handler.Handler4 = func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		return resp, false
	}
	var h6 handler.Handler6 = func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		return resp, false
	}

	resp4, stop4 := h4(nil, nil)
	assert.Nil(t, resp4)
	assert.False(t, stop4)

	resp6, stop6 := h6(nil, nil)
	assert.Nil(t, resp6)
	assert.False(t, stop6)
}

// unrelatedKey is a context key a caller might use for something of its own.
// RequestInfoFrom must not mistake a value stored under it for a RequestInfo.
type unrelatedKey struct{}

// TestRequestInfoRoundTrip covers every field with a non-zero value, since a
// field left out of WithRequestInfo's copy or RequestInfoFrom's type
// assertion would otherwise go unnoticed.
func TestRequestInfoRoundTrip(t *testing.T) {
	info := handler.RequestInfo{
		Interface: "eth0",
		IfIndex:   7,
		Peer:      netip.MustParseAddrPort("203.0.113.5:68"),
		Local:     netip.MustParseAddrPort("203.0.113.1:67"),
	}

	ctx := handler.WithRequestInfo(context.Background(), info)
	got, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, info, got)
}

// TestRequestInfoFromAbsent checks the two ways a context can carry no
// RequestInfo: never having one attached, and carrying a value under some
// other caller-defined key that must not be mistaken for one.
func TestRequestInfoFromAbsent(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
	}{
		{name: "background", ctx: context.Background()},
		{name: "unrelated value", ctx: context.WithValue(context.Background(), unrelatedKey{}, "value")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := handler.RequestInfoFrom(tc.ctx)
			assert.False(t, ok)
			assert.Zero(t, got)
		})
	}
}

// TestRequestInfoFromReturnsCopy makes sure a handler that edits the struct
// it got back cannot corrupt what a later RequestInfoFrom call on the same
// context returns.
func TestRequestInfoFromReturnsCopy(t *testing.T) {
	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth0"})

	got, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	got.Interface = "mutated"

	again, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, "eth0", again.Interface)
}

// TestWithRequestInfoNesting checks that wrapping a context that already
// carries a RequestInfo replaces it rather than merging or being shadowed by
// the outer one.
func TestWithRequestInfoNesting(t *testing.T) {
	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "outer"})
	ctx = handler.WithRequestInfo(ctx, handler.RequestInfo{Interface: "inner"})

	got, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, "inner", got.Interface)
}

// TestHandlerCtxTypes is TestHandlerTypes's counterpart for the context-aware
// handler types: it checks the shape compiles and that the context passed in
// is the one the handler reads back out, which is the entire point of these
// two types over the plain ones.
func TestHandlerCtxTypes(t *testing.T) {
	info := handler.RequestInfo{Interface: "eth0"}
	ctx := handler.WithRequestInfo(context.Background(), info)

	var h4 handler.Handler4Ctx = func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		got, ok := handler.RequestInfoFrom(ctx)
		assert.True(t, ok)
		assert.Equal(t, info, got)
		return resp, false
	}
	var h6 handler.Handler6Ctx = func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		got, ok := handler.RequestInfoFrom(ctx)
		assert.True(t, ok)
		assert.Equal(t, info, got)
		return resp, false
	}

	resp4, stop4 := h4(ctx, nil, nil)
	assert.Nil(t, resp4)
	assert.False(t, stop4)

	resp6, stop6 := h6(ctx, nil, nil)
	assert.Nil(t, resp6)
	assert.False(t, stop6)
}
