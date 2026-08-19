// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package dns_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/dns"
)

func TestSetup6(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := dns.Plugin.Setup6()
		assert.Error(t, err)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := dns.Plugin.Setup6("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h6, err := dns.Plugin.Setup6("2001:db8::1", "2001:db8::3")
		require.NoError(t, err)
		require.NotNil(t, h6)

		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		req.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionDNSRecursiveNameServer))

		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeReply

		resp, stop := h6(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)
		assert.Len(t, resp.(*dhcpv6.Message).Options.DNS(), 2)
	})
}

func TestSetup4(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := dns.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := dns.Plugin.Setup4("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h4, err := dns.Plugin.Setup4("192.0.2.1", "192.0.2.3")
		require.NoError(t, err)
		require.NotNil(t, h4)

		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer))
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		resp, stop := h4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)
		found := resp.DNS()
		require.Len(t, found, 2)
		assert.True(t, net.ParseIP("192.0.2.1").Equal(found[0]))
		assert.True(t, net.ParseIP("192.0.2.3").Equal(found[1]))
	})
}
