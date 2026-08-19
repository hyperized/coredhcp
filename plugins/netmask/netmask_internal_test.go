// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netmask

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckValidNetmask(t *testing.T) {
	assert.True(t, checkValidNetmask(net.IPv4Mask(255, 255, 255, 0)))
	assert.True(t, checkValidNetmask(net.IPv4Mask(255, 255, 0, 0)))
	assert.True(t, checkValidNetmask(net.IPv4Mask(255, 0, 0, 0)))
	assert.True(t, checkValidNetmask(net.IPv4Mask(0, 0, 0, 0)))

	assert.False(t, checkValidNetmask(net.IPv4Mask(0, 255, 255, 255)))
	assert.False(t, checkValidNetmask(net.IPv4Mask(0, 0, 255, 255)))
	assert.False(t, checkValidNetmask(net.IPv4Mask(0, 0, 0, 255)))
}

func TestPluginStateHandler4(t *testing.T) {
	p := &pluginState{netmask: net.IPv4Mask(255, 255, 255, 0)}

	req := &dhcpv4.DHCPv4{}
	resp := &dhcpv4.DHCPv4{
		Options: dhcpv4.Options{},
	}

	result, stop := p.Handler4(req, resp)
	require.Same(t, resp, result)
	assert.False(t, stop)
	assert.EqualValues(t, p.netmask, resp.Options.Get(dhcpv4.OptionSubnetMask))
}
