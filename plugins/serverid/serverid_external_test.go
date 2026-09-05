// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverid_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/serverid"
)

func TestSetup4(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := serverid.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := serverid.Plugin.Setup4("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("ipv6 address", func(t *testing.T) {
		_, err := serverid.Plugin.Setup4("2001:db8::1")
		assert.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)
		require.NotNil(t, h4)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
		assert.True(t, net.ParseIP("192.0.2.1").Equal(result.ServerIPAddr))
	})

	t.Run("option 54 for our server, accepted with our identifier stamped", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1").To4()))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
		assert.True(t, net.ParseIP("192.0.2.1").Equal(result.ServerIPAddr))
		assert.True(t, net.ParseIP("192.0.2.1").Equal(dhcpv4.GetIP(dhcpv4.OptionServerIdentifier, result.Options)))
	})

	t.Run("option 54 for a different server, dropped", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.9").To4()))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	// siaddr may be stale from an earlier exchange; only option 54 identifies the server.
	t.Run("stale siaddr without option 54, accepted", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest, ServerIPAddr: net.ParseIP("192.0.2.9").To4()}
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
	})

	t.Run("RELEASE with foreign option 54, dropped", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))
		req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.9").To4()))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("DECLINE with foreign option 54, dropped", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
		req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.9").To4()))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	// RFC 2131 Table 5: RELEASE and DECLINE MUST carry option 54, since both
	// are unicast to the server that owns the lease.
	requireServerIDCases := []struct {
		name        string
		messageType dhcpv4.MessageType
	}{
		{"RELEASE", dhcpv4.MessageTypeRelease},
		{"DECLINE", dhcpv4.MessageTypeDecline},
	}
	for _, tc := range requireServerIDCases {
		t.Run(tc.name+" with no option 54, dropped", func(t *testing.T) {
			h4, err := serverid.Plugin.Setup4("192.0.2.1")
			require.NoError(t, err)

			req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
			req.UpdateOption(dhcpv4.OptMessageType(tc.messageType))
			resp := &dhcpv4.DHCPv4{}

			result, stop := h4(req, resp)
			assert.Nil(t, result)
			assert.True(t, stop)
		})

		t.Run(tc.name+" with our option 54, accepted with our identifier stamped", func(t *testing.T) {
			h4, err := serverid.Plugin.Setup4("192.0.2.1")
			require.NoError(t, err)

			req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
			req.UpdateOption(dhcpv4.OptMessageType(tc.messageType))
			req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1").To4()))
			resp := &dhcpv4.DHCPv4{}

			result, stop := h4(req, resp)
			require.NotNil(t, result)
			assert.False(t, stop)
			assert.True(t, net.ParseIP("192.0.2.1").Equal(result.ServerIPAddr))
			assert.True(t, net.ParseIP("192.0.2.1").Equal(dhcpv4.GetIP(dhcpv4.OptionServerIdentifier, result.Options)))
		})
	}

	t.Run("REQUEST with no option 54, accepted", func(t *testing.T) {
		h4, err := serverid.Plugin.Setup4("192.0.2.1")
		require.NoError(t, err)

		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
	})
}

func TestSetup6(t *testing.T) {
	t.Run("too few args", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("ll")
		assert.Error(t, err)
	})

	t.Run("empty type", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
	})

	t.Run("empty value", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("ll", "")
		assert.Error(t, err)
	})

	t.Run("invalid MAC", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("ll", "not-a-mac")
		assert.Error(t, err)
	})

	t.Run("en/uuid not supported", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("en", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)

		_, err = serverid.Plugin.Setup6("uuid", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
	})

	t.Run("opaque type not supported", func(t *testing.T) {
		_, err := serverid.Plugin.Setup6("garbage", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
	})

	t.Run("valid LL", func(t *testing.T) {
		h6, err := serverid.Plugin.Setup6("ll", "aa:bb:cc:dd:ee:ff")
		require.NoError(t, err)
		require.NotNil(t, h6)
		assertHandler6Works(t, h6, "aa:bb:cc:dd:ee:ff")
	})

	t.Run("valid LLT via alias", func(t *testing.T) {
		h6, err := serverid.Plugin.Setup6("DUID-LLT", "aa:bb:cc:dd:ee:ff")
		require.NoError(t, err)
		require.NotNil(t, h6)
		assertHandler6Works(t, h6, "aa:bb:cc:dd:ee:ff")
	})
}

func assertHandler6Works(t *testing.T, h6 func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool), mac string) {
	t.Helper()

	hwaddr, err := net.ParseMAC(mac)
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRebind
	dhcpv6.WithClientID(&dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: hwaddr})(req)

	stub, err := dhcpv6.NewReplyFromMessage(req)
	require.NoError(t, err)

	resp, stop := h6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	opt := resp.(*dhcpv6.Message).Options.ServerID()
	require.NotNil(t, opt)
}
