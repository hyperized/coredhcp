// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/nbp"
)

func TestSetup6ArgValidation(t *testing.T) {
	_, err := nbp.Plugin.Setup6()
	require.Error(t, err)

	_, err = nbp.Plugin.Setup6("http://[::1")
	require.Error(t, err)
}

func TestSetup4ArgValidation(t *testing.T) {
	_, err := nbp.Plugin.Setup4()
	require.Error(t, err)

	_, err = nbp.Plugin.Setup4("http://[::1")
	require.Error(t, err)
}

func TestHandler6NotRequested(t *testing.T) {
	handler, err := nbp.Plugin.Setup6("http://[2001:db8::1]/nbp")
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)
	assert.Nil(t, resp.(*dhcpv6.Message).Options.GetOne(dhcpv6.OptionBootfileURL))
	assert.Nil(t, resp.(*dhcpv6.Message).Options.GetOne(dhcpv6.OptionBootfileParam))
}

func TestHandler6URLRequestedNoParams(t *testing.T) {
	handler, err := nbp.Plugin.Setup6("http://[2001:db8::1]/nbp")
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionBootfileURL, dhcpv6.OptionBootfileParam))
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)

	urlOpt := resp.(*dhcpv6.Message).Options.GetOne(dhcpv6.OptionBootfileURL)
	require.NotNil(t, urlOpt)
	assert.Equal(t, "http://[2001:db8::1]/nbp", string(urlOpt.ToBytes()))
	// No params were configured, so opt60 must not be added even though requested.
	assert.Nil(t, resp.(*dhcpv6.Message).Options.GetOne(dhcpv6.OptionBootfileParam))
}

func TestHandler6ParamsRequestedAndConfigured(t *testing.T) {
	handler, err := nbp.Plugin.Setup6("http://[2001:db8::1]/nbp?params=console=ttyS0")
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionBootfileParam))
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)

	paramOpt := resp.(*dhcpv6.Message).Options.GetOne(dhcpv6.OptionBootfileParam)
	require.NotNil(t, paramOpt)
	assert.Equal(t, "console=ttyS0", string(paramOpt.ToBytes()))
}

func TestHandler6DecapsulateError(t *testing.T) {
	handler, err := nbp.Plugin.Setup6("http://[2001:db8::1]/nbp")
	require.NoError(t, err)

	// Malformed: no relay-message option to decapsulate; the plugin must drop it, not panic or reply.
	req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	assert.Nil(t, resp)
	assert.True(t, stop)
}

func TestHandler4NeitherRequested(t *testing.T) {
	handler, err := nbp.Plugin.Setup4("tftp://10.0.0.1/nbp")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)
	assert.Empty(t, resp.TFTPServerName())
	assert.Empty(t, resp.BootFileNameOption())
}

func TestHandler4TFTPSchemeRequested(t *testing.T) {
	handler, err := nbp.Plugin.Setup4("tftp://10.0.0.1/nbp")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptParameterRequestList(dhcpv4.OptionTFTPServerName, dhcpv4.OptionBootfileName))
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)
	assert.Equal(t, "10.0.0.1", resp.TFTPServerName())
	assert.Equal(t, "/nbp", resp.BootFileNameOption())
}

func TestHandler4HTTPSchemeTFTPRequestedNotAdded(t *testing.T) {
	handler, err := nbp.Plugin.Setup4("http://10.0.0.1/nbp")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptParameterRequestList(dhcpv4.OptionTFTPServerName))
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)
	// The http scheme never populates opt66, so requesting it adds nothing even though configured.
	assert.Empty(t, resp.TFTPServerName())
}

func TestHandler4BootfileNameRequested(t *testing.T) {
	handler, err := nbp.Plugin.Setup4("http://10.0.0.1/nbp")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptParameterRequestList(dhcpv4.OptionBootfileName))
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp)
	assert.True(t, stop)
	assert.Equal(t, "http://10.0.0.1/nbp", resp.BootFileNameOption())
}
