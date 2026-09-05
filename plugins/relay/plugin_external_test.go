// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package relay_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins/relay"
)

var allowArgs = []string{"allow", "10.0.1.1", "10.0.2.0/24", "fe80::/10"}

func ctxFrom(t *testing.T, peer string) context.Context {
	t.Helper()
	return handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Interface: "eth0",
		IfIndex:   2,
		Peer:      netip.MustParseAddrPort(peer),
		Local:     netip.MustParseAddrPort("0.0.0.0:67"),
	})
}

func v4Exchange(t *testing.T, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.New(mods...)
	require.NoError(t, err)
	resp, err := dhcpv4.New()
	require.NoError(t, err)
	return req, resp
}

// depth 0 returns a plain client message; otherwise it's wrapped in depth
// Relay-forward layers, and an empty linkAddr leaves that field absent.
func request6(t *testing.T, depth int, linkAddr string, hopCount uint8) dhcpv6.DHCPv6 {
	t.Helper()
	inner, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	if depth == 0 {
		return inner
	}
	var link net.IP
	if linkAddr != "" {
		link = net.ParseIP(linkAddr)
	}
	var msg dhcpv6.DHCPv6 = inner
	for range depth {
		outer, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward, link, net.ParseIP("fe80::1"))
		require.NoError(t, err)
		msg = outer
	}
	relay, ok := msg.(*dhcpv6.RelayMessage)
	require.True(t, ok)
	relay.HopCount = hopCount
	return relay
}

func TestPluginRegistration(t *testing.T) {
	assert.Equal(t, "relay", relay.Plugin.Name)
	assert.NotNil(t, relay.Plugin.Setup4Ctx)
	assert.NotNil(t, relay.Plugin.Setup6Ctx)
	assert.Nil(t, relay.Plugin.Setup4, "the plain and context-aware setup functions are mutually exclusive")
	assert.Nil(t, relay.Plugin.Setup6)
}

func TestSetupErrors(t *testing.T) {
	t.Run("DHCPv4", func(t *testing.T) {
		h, err := relay.Plugin.Setup4Ctx("deny", "10.0.1.1")
		require.Error(t, err)
		assert.Nil(t, h)
	})
	t.Run("DHCPv6", func(t *testing.T) {
		h, err := relay.Plugin.Setup6Ctx("deny", "fe80::/10")
		require.Error(t, err)
		assert.Nil(t, h)
	})
}

func TestHandler4(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		mods     []dhcpv4.Modifier
		peer     string // empty means no request information at all
		wantDrop bool
	}{
		{
			name: "on-link client passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover)},
			peer: "10.0.9.9:68",
		},
		{
			name: "relay listed by address passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer: "10.0.1.1:67",
		},
		{
			name: "relay inside a listed prefix passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 2, 42}),
			},
			peer: "10.0.2.42:67",
		},
		{
			name: "unlisted giaddr is dropped",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{192, 0, 2, 5}),
			},
			peer:     "10.0.1.1:67",
			wantDrop: true,
		},
		{
			name: "IPv6 entries do not admit an IPv4 relay",
			args: []string{"allow", "fe80::/10"},
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer:     "10.0.1.1:67",
			wantDrop: true,
		},
		{
			name: "relayed request without request information is dropped",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			wantDrop: true,
		},
		{
			name: "strict-giaddr passes a matching source",
			args: append(append([]string{}, allowArgs...), "strict-giaddr"),
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer: "10.0.1.1:67",
		},
		{
			name: "strict-giaddr drops a differing source",
			args: append(append([]string{}, allowArgs...), "strict-giaddr"),
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer:     "10.0.2.7:67",
			wantDrop: true,
		},
		{
			name: "a differing source passes without strict-giaddr",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer: "10.0.2.7:67",
		},
		{
			name: "release from its own address passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
				dhcpv4.WithClientIP(net.IP{10, 0, 9, 9}),
			},
			peer: "10.0.9.9:68",
		},
		{
			name: "release from another address is dropped",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
				dhcpv4.WithClientIP(net.IP{10, 0, 9, 9}),
			},
			peer:     "10.0.9.10:68",
			wantDrop: true,
		},
		{
			name: "release without ciaddr is dropped",
			args: allowArgs,
			mods: []dhcpv4.Modifier{dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease)},
			peer: "10.0.9.9:68",

			wantDrop: true,
		},
		{
			name: "release without request information passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
				dhcpv4.WithClientIP(net.IP{10, 0, 9, 9}),
			},
		},
		{
			name: "release-check off lets a mismatched release through",
			args: append(append([]string{}, allowArgs...), "release-check:off"),
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
				dhcpv4.WithClientIP(net.IP{10, 0, 9, 9}),
			},
			peer: "10.0.9.10:68",
		},
		{
			name: "decline has no address to compare and passes",
			args: allowArgs,
			mods: []dhcpv4.Modifier{dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline)},
			peer: "10.0.9.9:68",
		},
		{
			name: "a relayed release is judged by giaddr, not by ciaddr",
			args: allowArgs,
			mods: []dhcpv4.Modifier{
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
				dhcpv4.WithClientIP(net.IP{10, 0, 9, 9}),
				dhcpv4.WithGatewayIP(net.IP{10, 0, 1, 1}),
			},
			peer: "10.0.1.1:67",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := relay.Plugin.Setup4Ctx(tc.args...)
			require.NoError(t, err)

			ctx := context.Background()
			if tc.peer != "" {
				ctx = ctxFrom(t, tc.peer)
			}
			req, resp := v4Exchange(t, tc.mods...)

			got, stop := h(ctx, req, resp)
			if tc.wantDrop {
				assert.Nil(t, got)
				assert.True(t, stop, "a dropped request ends the chain")
				return
			}
			assert.Same(t, resp, got)
			assert.False(t, stop, "an accepted request continues the chain")
		})
	}
}

func TestHandler6(t *testing.T) {
	const someLink = "2001:db8::1"

	cases := []struct {
		name     string
		args     []string
		depth    int    // 0 builds a plain, unrelayed client message
		linkAddr string // empty leaves the outermost link address absent
		hopCount uint8
		peer     string // empty means no request information at all
		wantDrop bool
	}{
		{
			name: "a client message that was not relayed passes",
			args: allowArgs,
			peer: "[2001:db8::99]:546",
		},
		{
			name:     "a link-local relay passes",
			args:     allowArgs,
			depth:    1,
			linkAddr: someLink,
			peer:     "[fe80::1]:547",
		},
		{
			name:     "an unlisted relay source is dropped",
			args:     allowArgs,
			depth:    1,
			linkAddr: someLink,
			peer:     "[2001:db8::1]:547",
			wantDrop: true,
		},
		{
			name:     "IPv4 entries do not admit an IPv6 relay",
			args:     []string{"allow", "10.0.1.1"},
			depth:    1,
			linkAddr: someLink,
			peer:     "[fe80::1]:547",
			wantDrop: true,
		},
		{
			name:     "a relayed request without request information is dropped",
			args:     allowArgs,
			depth:    1,
			linkAddr: someLink,
			wantDrop: true,
		},
		{
			name:     "no link address and a hop count above the limit is dropped",
			args:     allowArgs,
			depth:    1,
			hopCount: 33,
			peer:     "[fe80::1]:547",
			wantDrop: true,
		},
		{
			name:     "no link address at the hop count limit passes",
			args:     allowArgs,
			depth:    1,
			hopCount: 32,
			peer:     "[fe80::1]:547",
		},
		{
			name:     "a high hop count with a link address passes",
			args:     allowArgs,
			depth:    1,
			linkAddr: someLink,
			hopCount: 200,
			peer:     "[fe80::1]:547",
		},
		{
			name:     "eight nested relays pass",
			args:     allowArgs,
			depth:    8,
			linkAddr: someLink,
			peer:     "[fe80::1]:547",
		},
		{
			name:     "nine nested relays are dropped",
			args:     allowArgs,
			depth:    9,
			linkAddr: someLink,
			peer:     "[fe80::1]:547",
			wantDrop: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := relay.Plugin.Setup6Ctx(tc.args...)
			require.NoError(t, err)

			ctx := context.Background()
			if tc.peer != "" {
				ctx = ctxFrom(t, tc.peer)
			}
			resp, err := dhcpv6.NewMessage()
			require.NoError(t, err)

			got, stop := h(ctx, request6(t, tc.depth, tc.linkAddr, tc.hopCount), resp)
			if tc.wantDrop {
				assert.Nil(t, got)
				assert.True(t, stop, "a dropped request ends the chain")
				return
			}
			assert.Same(t, resp, got)
			assert.False(t, stop, "an accepted request continues the chain")
		})
	}
}
