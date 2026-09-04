// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverid

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestDUID(uuid string) dhcpv6.DUID {
	var uuidb [16]byte
	copy(uuidb[:], uuid)
	return &dhcpv6.DUIDUUID{
		UUID: uuidb,
	}
}

func TestPluginState6Handler6(t *testing.T) {
	serverID := makeTestDUID("0000000000000000")
	p := &pluginState6{serverID: serverID}

	t.Run("decapsulation error", func(t *testing.T) {
		relay := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeRelayReply

		resp, stop := p.Handler6(relay, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("must-discard type rejects any server ID", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeSolicit
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)
		dhcpv6.WithServerID(serverID)(req)

		stub, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		resp, stop := p.Handler6(req, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("mismatched server ID rejected", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRenew
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)
		dhcpv6.WithServerID(makeTestDUID("0000000000000001"))(req)

		stub, err := dhcpv6.NewReplyFromMessage(req)
		require.NoError(t, err)

		resp, stop := p.Handler6(req, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("matching server ID accepted", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRenew
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)
		dhcpv6.WithServerID(serverID)(req)

		stub, err := dhcpv6.NewReplyFromMessage(req)
		require.NoError(t, err)

		resp, stop := p.Handler6(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)

		opt := resp.(*dhcpv6.Message).Options.ServerID()
		require.NotNil(t, opt)
		assert.True(t, opt.Equal(serverID))
	})

	t.Run("required type without server ID rejected", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)

		stub, err := dhcpv6.NewReplyFromMessage(req)
		require.NoError(t, err)

		resp, stop := p.Handler6(req, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("optional type without server ID accepted", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRebind
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)

		stub, err := dhcpv6.NewReplyFromMessage(req)
		require.NoError(t, err)

		resp, _ := p.Handler6(req, stub)
		require.NotNil(t, resp)

		opt := resp.(*dhcpv6.Message).Options.ServerID()
		require.NotNil(t, opt)
		assert.True(t, opt.Equal(serverID))
	})

	t.Run("relayed message with server ID rejected", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeSolicit
		dhcpv6.WithClientID(makeTestDUID("1000000000000000"))(req)
		dhcpv6.WithServerID(serverID)(req)

		stub, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		relayedRequest, err := dhcpv6.EncapsulateRelay(req, dhcpv6.MessageTypeRelayForward, net.IPv6loopback, net.IPv6loopback)
		require.NoError(t, err)

		resp, stop := p.Handler6(relayedRequest, stub)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})
}

func TestPluginState4Handler4(t *testing.T) {
	serverID := net.ParseIP("192.0.2.1").To4()
	otherID := net.ParseIP("192.0.2.9").To4()
	p := &pluginState4{serverID: serverID}

	t.Run("not a boot request", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootReply}
		resp := &dhcpv4.DHCPv4{}

		result, stop := p.Handler4(req, resp)
		assert.Same(t, resp, result)
		assert.False(t, stop)
		assert.Nil(t, result.ServerIPAddr)
	})

	t.Run("no option 54 set, accepted", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		resp := &dhcpv4.DHCPv4{}

		result, stop := p.Handler4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
		assert.True(t, serverID.Equal(result.ServerIPAddr))

		sid := dhcpv4.GetIP(dhcpv4.OptionServerIdentifier, result.Options)
		assert.True(t, serverID.Equal(sid))
	})

	// The old code keyed off req.ServerIPAddr (siaddr), which a client may
	// carry over from an earlier exchange even though it has nothing to do
	// with which DHCP server the request is for. This used to be rejected;
	// now that the guard looks only at option 54, a request with no option
	// 54 passes regardless of siaddr.
	t.Run("siaddr points elsewhere but no option 54, accepted", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest, ServerIPAddr: otherID}
		resp := &dhcpv4.DHCPv4{}

		result, stop := p.Handler4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
	})

	t.Run("option 54 matches, accepted", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptServerIdentifier(serverID))
		resp := &dhcpv4.DHCPv4{}

		result, stop := p.Handler4(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
	})

	t.Run("option 54 mismatches, rejected", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
		req.UpdateOption(dhcpv4.OptServerIdentifier(otherID))
		resp := &dhcpv4.DHCPv4{}

		result, stop := p.Handler4(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	messageTypeCases := []struct {
		name        string
		messageType dhcpv4.MessageType
	}{
		{"REQUEST with foreign option 54 rejected", dhcpv4.MessageTypeRequest},
		{"RELEASE with foreign option 54 rejected", dhcpv4.MessageTypeRelease},
		{"DECLINE with foreign option 54 rejected", dhcpv4.MessageTypeDecline},
	}
	for _, tc := range messageTypeCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dhcpv4.DHCPv4{OpCode: dhcpv4.OpcodeBootRequest}
			req.UpdateOption(dhcpv4.OptMessageType(tc.messageType))
			req.UpdateOption(dhcpv4.OptServerIdentifier(otherID))
			resp := &dhcpv4.DHCPv4{}

			result, stop := p.Handler4(req, resp)
			assert.Nil(t, result)
			assert.True(t, stop)
		})
	}
}
