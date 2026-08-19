// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ipv6only_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/ipv6only"
)

func TestSetup4InvalidDuration(t *testing.T) {
	_, err := ipv6only.Plugin.Setup4("not-a-duration")
	require.Error(t, err)
	require.EqualError(t, err, "ipv6only failed to initialize")
}

func TestHandler4OptionRequested(t *testing.T) {
	handler, err := ipv6only.Plugin.Setup4("4660s")
	require.NoError(t, err)
	require.NotNil(t, handler)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptParameterRequestList(dhcpv4.OptionBroadcastAddress, dhcpv4.OptionIPv6OnlyPreferred))
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.True(t, stop, "plugin did not interrupt processing")

	opt := resp.Options.Get(dhcpv4.OptionIPv6OnlyPreferred)
	require.NotNil(t, opt, "plugin did not return the IPv6-Only Preferred option")
	require.Equal(t, []byte{0x00, 0x00, 0x12, 0x34}, opt)
}

func TestHandler4OptionNotRequested(t *testing.T) {
	handler, err := ipv6only.Plugin.Setup4()
	require.NoError(t, err)
	require.NotNil(t, handler)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := handler(req, stub)
	require.NotNil(t, resp, "plugin did not return a message")
	require.False(t, stop, "plugin interrupted processing")
	require.Nil(t, resp.Options.Get(dhcpv4.OptionIPv6OnlyPreferred), "found IPv6-Only Preferred option when not requested")
}
