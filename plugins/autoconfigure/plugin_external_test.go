// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package autoconfigure_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/autoconfigure"
)

func TestSetup4InvalidValue(t *testing.T) {
	_, err := autoconfigure.Plugin.Setup4("bogus")
	require.Error(t, err)
	require.EqualError(t, err, "unexpected value 'bogus' for autoconfigure argument")
}

func TestSetup4TooManyArguments(t *testing.T) {
	_, err := autoconfigure.Plugin.Setup4("1", "extra")
	require.Error(t, err)
	require.EqualError(t, err, "too many arguments")
}

func newOfferStub(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	t.Helper()
	stub, err := dhcpv4.NewReplyFromRequest(req, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
	require.NoError(t, err)
	return stub
}

func TestHandler4OptionRequestedDefault(t *testing.T) {
	handler, err := autoconfigure.Plugin.Setup4()
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionAutoConfigure, []byte{1}))
	stub := newOfferStub(t, req)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.False(t, stop, "plugin interrupted processing")

	opt := resp.Options.Get(dhcpv4.OptionAutoConfigure)
	require.NotNil(t, opt, "plugin did not return the Auto-Configure option")
	require.Equal(t, []byte{0}, opt)
}

func TestHandler4OptionRequestedConfigured(t *testing.T) {
	handler, err := autoconfigure.Plugin.Setup4("1")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionAutoConfigure, []byte{1}))
	stub := newOfferStub(t, req)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.False(t, stop, "plugin interrupted processing")

	opt := resp.Options.Get(dhcpv4.OptionAutoConfigure)
	require.NotNil(t, opt, "plugin did not return the Auto-Configure option")
	require.Equal(t, []byte{1}, opt)
}

func TestHandler4NotOfferMessage(t *testing.T) {
	handler, err := autoconfigure.Plugin.Setup4()
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionAutoConfigure, []byte{1}))
	// A reply without WithMessageType keeps no message type, which is never MessageTypeOffer.
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.False(t, stop, "plugin interrupted processing")
	require.Nil(t, resp.Options.Get(dhcpv4.OptionAutoConfigure), "plugin responded with AutoConfigure option")
}

func TestHandler4AssignedIP(t *testing.T) {
	handler, err := autoconfigure.Plugin.Setup4()
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub := newOfferStub(t, req)
	stub.YourIPAddr = net.ParseIP("192.0.2.100")

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.False(t, stop, "plugin interrupted processing")
	require.Nil(t, resp.Options.Get(dhcpv4.OptionAutoConfigure), "plugin responded with AutoConfigure option")
}

func TestHandler4NoIPNotRequested(t *testing.T) {
	handler, err := autoconfigure.Plugin.Setup4()
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub := newOfferStub(t, req)

	resp, stop := handler(req, stub)
	require.Nil(t, resp, "plugin returned a message")
	require.True(t, stop, "plugin did not interrupt processing")
}
