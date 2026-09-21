// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package staticroute_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/staticroute"
)

func TestSetup4ArgValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "no args", args: nil, wantErr: "no static route given"},
		{name: "invalid pair", args: []string{"foo"}, wantErr: `route "foo" is not a destination and gateway pair`},
		{name: "invalid destination", args: []string{"foo,"}, wantErr: `destination "foo" is not a CIDR subnet`},
		{name: "invalid gateway", args: []string{"10.0.0.0/8,foo"}, wantErr: `gateway "foo" is not an IPv4 address`},
		{name: "IPv6 destination", args: []string{"2001:db8::/32,192.168.1.1"}, wantErr: `destination "2001:db8::/32" is not an IPv4 subnet`},
		{name: "IPv6 gateway", args: []string{"10.0.0.0/8,2001:db8::1"}, wantErr: `gateway "2001:db8::1" is not an IPv4 address`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := staticroute.Plugin.Setup4(tc.args...)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestHandler4SingleRoute(t *testing.T) {
	handler, err := staticroute.Plugin.Setup4("10.0.0.0/8,192.168.1.1")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	var got dhcpv4.Routes
	require.NoError(t, got.FromBytes(resp.Options.Get(dhcpv4.OptionClasslessStaticRoute)))
	require.Len(t, got, 1)
	assert.Equal(t, "10.0.0.0/8", got[0].Dest.String())
	assert.Equal(t, "192.168.1.1", got[0].Router.String())
}

func TestHandler4MultipleRoutes(t *testing.T) {
	handler, err := staticroute.Plugin.Setup4("10.0.0.0/8,192.168.1.1", "192.168.2.0/24,192.168.1.100")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	var got dhcpv4.Routes
	require.NoError(t, got.FromBytes(resp.Options.Get(dhcpv4.OptionClasslessStaticRoute)))
	require.Len(t, got, 2)
	assert.Equal(t, "10.0.0.0/8", got[0].Dest.String())
	assert.Equal(t, "192.168.1.1", got[0].Router.String())
	assert.Equal(t, "192.168.2.0/24", got[1].Dest.String())
	assert.Equal(t, "192.168.1.100", got[1].Router.String())
}
