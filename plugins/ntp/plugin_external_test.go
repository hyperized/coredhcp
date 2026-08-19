// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ntp_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/ntp"
)

func TestSetup4Errors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no args", args: nil},
		{name: "unparseable address", args: []string{"not-an-ip"}},
		{name: "ipv6 address", args: []string{"2001:db8::1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ntp.Plugin.Setup4(tc.args...)
			assert.Error(t, err)
			assert.Nil(t, h)
		})
	}
}

func TestSetup6Errors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no args", args: nil},
		{name: "unparseable address", args: []string{"not-an-ip"}},
		{name: "ipv4 address", args: []string{"192.0.2.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ntp.Plugin.Setup6(tc.args...)
			assert.Error(t, err)
			assert.Nil(t, h)
		})
	}
}

func TestSetup4(t *testing.T) {
	h4, err := ntp.Plugin.Setup4("192.0.2.1", "192.0.2.3")
	require.NoError(t, err)
	require.NotNil(t, h4)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := h4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	// Option 42, in configuration order.
	found := resp.NTPServers()
	require.Len(t, found, 2)
	assert.True(t, net.ParseIP("192.0.2.1").Equal(found[0]))
	assert.True(t, net.ParseIP("192.0.2.3").Equal(found[1]))
}

func TestSetup6(t *testing.T) {
	h6, err := ntp.Plugin.Setup6("2001:db8::1", "2001:db8::3")
	require.NoError(t, err)
	require.NotNil(t, h6)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest

	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub.MessageType = dhcpv6.MessageTypeReply

	resp, stop := h6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	msg, ok := resp.(*dhcpv6.Message)
	require.True(t, ok)

	found := msg.Options.NTPServers()
	require.Len(t, found, 2)
	assert.True(t, net.ParseIP("2001:db8::1").Equal(found[0]))
	assert.True(t, net.ParseIP("2001:db8::3").Equal(found[1]))

	// Confirm the RFC 5908 shape: one typed NTPSuboptionSrvAddr per
	// configured server, in order, rather than a hand-rolled encoding.
	opt := msg.Options.GetOne(dhcpv6.OptionNTPServer)
	require.NotNil(t, opt)
	ntpOpt, ok := opt.(*dhcpv6.OptNTPServer)
	require.True(t, ok)
	require.Len(t, ntpOpt.Suboptions, 2)
	for _, subopt := range ntpOpt.Suboptions {
		_, ok := subopt.(*dhcpv6.NTPSuboptionSrvAddr)
		assert.True(t, ok)
	}
}
