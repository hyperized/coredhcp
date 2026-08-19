// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package router

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginStateHandler4(t *testing.T) {
	routers := []net.IP{
		net.ParseIP("192.0.2.1").To4(),
		net.ParseIP("192.0.2.3").To4(),
	}
	p := &pluginState{routers: routers}

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := p.Handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	found := resp.Router()
	require.Len(t, found, len(routers))
	for i, r := range routers {
		assert.True(t, r.Equal(found[i]))
	}
}
