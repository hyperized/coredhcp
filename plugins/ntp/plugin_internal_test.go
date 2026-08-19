// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ntp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup4(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "no args", args: nil, wantErr: true},
		{name: "unparseable address", args: []string{"not-an-ip"}, wantErr: true},
		{name: "ipv6 address", args: []string{"2001:db8::1"}, wantErr: true},
		{name: "valid mixed with invalid", args: []string{"192.0.2.1", "not-an-ip"}, wantErr: true},
		{name: "single valid", args: []string{"192.0.2.1"}, wantErr: false},
		{name: "multiple valid", args: []string{"192.0.2.1", "192.0.2.3"}, wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := setup4(tc.args...)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, h)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, h)
		})
	}
}

func TestSetup6(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "no args", args: nil, wantErr: true},
		{name: "unparseable address", args: []string{"not-an-ip"}, wantErr: true},
		{name: "ipv4 address", args: []string{"192.0.2.1"}, wantErr: true},
		{name: "valid mixed with invalid", args: []string{"2001:db8::1", "not-an-ip"}, wantErr: true},
		{name: "single valid", args: []string{"2001:db8::1"}, wantErr: false},
		{name: "multiple valid", args: []string{"2001:db8::1", "2001:db8::3"}, wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := setup6(tc.args...)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, h)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, h)
		})
	}
}

func TestPluginStateHandler4(t *testing.T) {
	servers := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.3"),
	}
	p := &pluginState{ntpServers: servers}

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := p.Handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	found := resp.NTPServers()
	require.Len(t, found, len(servers))
	for i, srv := range servers {
		assert.True(t, srv.Equal(found[i]))
	}
}

func TestPluginStateHandler6(t *testing.T) {
	servers := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::3"),
	}
	p := &pluginState{ntpServers: servers}

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest

	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub.MessageType = dhcpv6.MessageTypeReply

	resp, stop := p.Handler6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	found := resp.(*dhcpv6.Message).Options.NTPServers()
	require.Len(t, found, len(servers))
	for i, srv := range servers {
		assert.True(t, srv.Equal(found[i]))
	}
}

func TestPluginStateHandler6NoServers(t *testing.T) {
	p := &pluginState{}

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := p.Handler6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Empty(t, resp.(*dhcpv6.Message).Options.NTPServers())
}
