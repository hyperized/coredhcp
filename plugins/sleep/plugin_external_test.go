// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package sleep_test

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/sleep"
)

// delay is kept tiny so the tests stay fast; behaviour under test is "did we
// wait at least this long", not precise timing.
const delay = time.Millisecond

func TestSetup6ArgErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no args", args: nil},
		{name: "too many args", args: []string{"1ms", "2ms"}},
		{name: "invalid duration", args: []string{"not-a-duration"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := sleep.Plugin.Setup6(tc.args...)
			assert.Error(t, err)
			assert.Nil(t, h)
		})
	}
}

func TestSetup4ArgErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no args", args: nil},
		{name: "too many args", args: []string{"1ms", "2ms"}},
		{name: "invalid duration", args: []string{"not-a-duration"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := sleep.Plugin.Setup4(tc.args...)
			assert.Error(t, err)
			assert.Nil(t, h)
		})
	}
}

func TestHandler6Delays(t *testing.T) {
	h, err := sleep.Plugin.Setup6(delay.String())
	require.NoError(t, err)
	require.NotNil(t, h)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	start := time.Now()
	got, stop := h(req, resp)
	elapsed := time.Since(start)

	assert.Same(t, resp, got)
	assert.False(t, stop)
	assert.GreaterOrEqual(t, elapsed, delay)
}

func TestHandler4Delays(t *testing.T) {
	h, err := sleep.Plugin.Setup4(delay.String())
	require.NoError(t, err)
	require.NotNil(t, h)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	start := time.Now()
	got, stop := h(req, resp)
	elapsed := time.Since(start)

	assert.Same(t, resp, got)
	assert.False(t, stop)
	assert.GreaterOrEqual(t, elapsed, delay)
}
