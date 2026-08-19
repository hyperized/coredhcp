// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netmask_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/netmask"
)

func TestSetup4(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		h4, err := netmask.Plugin.Setup4("255.255.255.0")
		require.NoError(t, err)
		require.NotNil(t, h4)

		req := &dhcpv4.DHCPv4{}
		resp := &dhcpv4.DHCPv4{Options: dhcpv4.Options{}}
		result, stop := h4(req, resp)
		require.Same(t, resp, result)
		assert.False(t, stop)
		assert.EqualValues(t, net.IPv4Mask(255, 255, 255, 0), resp.Options.Get(dhcpv4.OptionSubnetMask))
	})

	t.Run("no configuration", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("too many args", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4("255.255.255.0", "255.255.0.0")
		assert.Error(t, err)
	})

	t.Run("unspecified netmask", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4("0.0.0.0")
		assert.Error(t, err)
	})

	t.Run("ipv6 address", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4("2001:db8::1")
		assert.Error(t, err)
	})

	t.Run("unparseable address", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("invalid netmask", func(t *testing.T) {
		_, err := netmask.Plugin.Setup4("0.0.0.255")
		assert.Error(t, err)
	})
}
