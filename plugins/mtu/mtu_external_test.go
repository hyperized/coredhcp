// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package mtu_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/mtu"
)

func TestSetup4(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("too many args", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4("1500", "1400")
		assert.Error(t, err)
	})

	t.Run("not a number", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4("not-a-number")
		assert.Error(t, err)
	})

	t.Run("below minimum", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4("67")
		assert.Error(t, err)
	})

	t.Run("above maximum", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4("65536")
		assert.Error(t, err)
	})

	t.Run("boundaries", func(t *testing.T) {
		_, err := mtu.Plugin.Setup4("68")
		assert.NoError(t, err)

		_, err = mtu.Plugin.Setup4("65535")
		assert.NoError(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h4, err := mtu.Plugin.Setup4("1500")
		require.NoError(t, err)
		require.NotNil(t, h4)

		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, dhcpv4.WithRequestedOptions(dhcpv4.OptionInterfaceMTU))
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		resp, stop := h4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)

		rMTU, err := dhcpv4.GetUint16(dhcpv4.OptionInterfaceMTU, resp.Options)
		require.NoError(t, err)
		assert.EqualValues(t, 1500, rMTU)
	})
}
