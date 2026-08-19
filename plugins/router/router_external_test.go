// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package router_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/router"
)

func TestSetup4(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := router.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := router.Plugin.Setup4("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h4, err := router.Plugin.Setup4("192.0.2.1", "192.0.2.3")
		require.NoError(t, err)
		require.NotNil(t, h4)

		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		resp, stop := h4(req, stub)
		require.NotNil(t, resp)
		assert.False(t, stop)
		found := resp.Router()
		require.Len(t, found, 2)
		assert.True(t, net.ParseIP("192.0.2.1").Equal(found[0]))
		assert.True(t, net.ParseIP("192.0.2.3").Equal(found[1]))
	})
}
