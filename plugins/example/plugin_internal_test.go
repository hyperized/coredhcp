// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package example

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup6(t *testing.T) {
	h, err := setup6()
	require.NoError(t, err)
	assert.NotNil(t, h)
}

func TestSetup4(t *testing.T) {
	h, err := setup4()
	require.NoError(t, err)
	assert.NotNil(t, h)
}

func TestExampleHandler6(t *testing.T) {
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	got, stop := exampleHandler6(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
}

func TestExampleHandler4(t *testing.T) {
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	got, stop := exampleHandler4(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
}
