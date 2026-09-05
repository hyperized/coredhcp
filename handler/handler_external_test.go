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

// A compile-time shape check: the package declares nothing but function types.
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

// Proves a value under another key is not mistaken for a RequestInfo.
type unrelatedKey struct{}

// Every field carries a non-zero value: one left out of the copy would
// otherwise go unnoticed.
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

// The two ways a context carries none: never attached, or under another key.
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

// Editing what one call returns must not corrupt what the next call returns.
func TestRequestInfoFromReturnsCopy(t *testing.T) {
	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth0"})

	got, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	got.Interface = "mutated"

	again, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, "eth0", again.Interface)
}

// Wrapping replaces the inner RequestInfo rather than merging with it.
func TestWithRequestInfoNesting(t *testing.T) {
	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "outer"})
	ctx = handler.WithRequestInfo(ctx, handler.RequestInfo{Interface: "inner"})

	got, ok := handler.RequestInfoFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, "inner", got.Interface)
}

// Reading the context back out is the whole point of the Ctx types.
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
