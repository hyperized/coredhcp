// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package searchdomains_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/searchdomains"
)

func TestAddDomains6(t *testing.T) {
	searchDomains := []string{"domain.a", "domain.b"}

	handler6, err := searchdomains.Plugin.Setup6(searchDomains...)
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest
	req.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionDNSRecursiveNameServer))

	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub.MessageType = dhcpv6.MessageTypeReply

	resp, stop := handler6(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	assert.False(t, stop, "plugin interrupted processing")

	searchLabels := resp.(*dhcpv6.Message).Options.DomainSearchList().Labels
	assert.Equal(t, searchDomains, searchLabels)
}

func TestAddDomains6EmptyList(t *testing.T) {
	handler6, err := searchdomains.Plugin.Setup6()
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := handler6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Empty(t, resp.(*dhcpv6.Message).Options.DomainSearchList().Labels)
}

func TestAddDomains4(t *testing.T) {
	// Different from the v6 domains, to catch v4/v6 cross-contamination.
	searchDomains := []string{"domain.b", "domain.c"}

	handler4, err := searchdomains.Plugin.Setup4(searchDomains...)
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)

	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler4(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	assert.False(t, stop, "plugin interrupted processing")

	searchLabels := resp.DomainSearch().Labels
	assert.Equal(t, searchDomains, searchLabels)
}

func TestAddDomains4EmptyList(t *testing.T) {
	handler4, err := searchdomains.Plugin.Setup4()
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	// dhcpv4's DomainSearch() accessor treats a zero-byte list as absent; assert the raw option instead.
	assert.True(t, resp.Options.Has(dhcpv4.OptionDNSDomainSearchList))
	assert.Empty(t, resp.Options.Get(dhcpv4.OptionDNSDomainSearchList))
}
