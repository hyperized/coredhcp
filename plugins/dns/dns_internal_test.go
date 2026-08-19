// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package dns

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginStateHandler6(t *testing.T) {
	servers := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::3"),
	}
	p := &pluginState{dnsServers: servers}

	t.Run("requested", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		req.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionDNSRecursiveNameServer))

		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeReply

		resp, stop := p.Handler6(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)

		found := resp.(*dhcpv6.Message).Options.DNS()
		assert.Equal(t, servers, found)
	})

	t.Run("not requested", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		req.AddOption(dhcpv6.OptRequestedOption())

		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeReply

		resp, stop := p.Handler6(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)

		opts := resp.GetOption(dhcpv6.OptionDNSRecursiveNameServer)
		assert.Empty(t, opts)
	})

	t.Run("decapsulation error", func(t *testing.T) {
		// A relay message with no embedded RelayMessage option fails to
		// decapsulate.
		relay := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}

		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeRelayReply

		resp, stop := p.Handler6(relay, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})
}

func TestPluginStateHandler4(t *testing.T) {
	servers := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.3"),
	}
	p := &pluginState{dnsServers: servers}

	t.Run("requested", func(t *testing.T) {
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer))
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		resp, stop := p.Handler4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)
		found := resp.DNS()
		require.Len(t, found, len(servers))
		for i, srv := range servers {
			assert.True(t, srv.Equal(found[i]))
		}
	})

	t.Run("not requested", func(t *testing.T) {
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		req.UpdateOption(dhcpv4.OptParameterRequestList(dhcpv4.OptionBroadcastAddress))

		resp, stop := p.Handler4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)
		assert.Empty(t, dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, resp.Options))
	})
}
