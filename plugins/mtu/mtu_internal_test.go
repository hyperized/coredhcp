// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package mtu

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginStateHandler4(t *testing.T) {
	p := &pluginState{mtu: 1500}

	t.Run("requested", func(t *testing.T) {
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, dhcpv4.WithRequestedOptions(dhcpv4.OptionInterfaceMTU))
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		resp, stop := p.Handler4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)

		rMTU, err := dhcpv4.GetUint16(dhcpv4.OptionInterfaceMTU, resp.Options)
		require.NoError(t, err)
		assert.Equal(t, p.mtu, rMTU)
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

		_, err = dhcpv4.GetUint16(dhcpv4.OptionInterfaceMTU, resp.Options)
		assert.Error(t, err)
	})
}
