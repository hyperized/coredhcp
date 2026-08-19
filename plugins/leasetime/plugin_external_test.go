// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasetime_test

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/leasetime"
)

func TestPluginWiring(t *testing.T) {
	assert.Equal(t, "lease_time", leasetime.Plugin.Name)
	assert.Nil(t, leasetime.Plugin.Setup6)
	assert.NotNil(t, leasetime.Plugin.Setup4)
}

func TestSetup4NoArgs(t *testing.T) {
	_, err := leasetime.Plugin.Setup4()
	assert.EqualError(t, err, "lease_time failed to initialize")
}

func TestSetup4InvalidDuration(t *testing.T) {
	_, err := leasetime.Plugin.Setup4("not-a-duration")
	assert.EqualError(t, err, "lease_time failed to initialize")
}

func TestSetup4Valid(t *testing.T) {
	h, err := leasetime.Plugin.Setup4("2h")
	require.NoError(t, err)
	require.NotNil(t, h)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	got, stop := h(req, resp)
	require.NotNil(t, got)
	assert.False(t, stop)
	assert.Equal(t, 2*time.Hour, got.IPAddressLeaseTime(0))
}
