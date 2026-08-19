// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		_, err := parseArgs()
		require.Error(t, err)
		assert.Equal(t, "exactly one argument must be passed to NBP plugin, got 0", err.Error())
	})

	t.Run("too many arguments", func(t *testing.T) {
		_, err := parseArgs("http://a/b", "http://c/d")
		require.Error(t, err)
		assert.Equal(t, "exactly one argument must be passed to NBP plugin, got 2", err.Error())
	})

	t.Run("valid URL", func(t *testing.T) {
		u, err := parseArgs("tftp://10.0.0.1/nbp")
		require.NoError(t, err)
		assert.Equal(t, "tftp", u.Scheme)
		assert.Equal(t, "10.0.0.1", u.Host)
		assert.Equal(t, "/nbp", u.Path)
	})

	t.Run("malformed URL", func(t *testing.T) {
		_, err := parseArgs("http://[::1")
		require.Error(t, err)
	})
}

func TestSetup6(t *testing.T) {
	t.Run("wrong argument count", func(t *testing.T) {
		h, err := setup6()
		assert.Nil(t, h)
		require.Error(t, err)
	})

	t.Run("malformed URL", func(t *testing.T) {
		h, err := setup6("http://[::1")
		assert.Nil(t, h)
		require.Error(t, err)
	})

	t.Run("no params", func(t *testing.T) {
		h, err := setup6("http://[2001:db8::1]/nbp")
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("with params", func(t *testing.T) {
		h, err := setup6("http://[2001:db8::1]/nbp?params=console=ttyS0")
		require.NoError(t, err)
		require.NotNil(t, h)
	})
}

func TestSetup4(t *testing.T) {
	t.Run("wrong argument count", func(t *testing.T) {
		h, err := setup4()
		assert.Nil(t, h)
		require.Error(t, err)
	})

	t.Run("malformed URL", func(t *testing.T) {
		h, err := setup4("http://[::1")
		assert.Nil(t, h)
		require.Error(t, err)
	})

	t.Run("http scheme", func(t *testing.T) {
		h, err := setup4("http://10.0.0.1/nbp")
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("tftp (default) scheme", func(t *testing.T) {
		h, err := setup4("tftp://10.0.0.1/nbp")
		require.NoError(t, err)
		require.NotNil(t, h)
	})
}

// TestHandler6Unconfigured exercises the opt59==nil branch of Handler6,
// which setup6 never produces (it always sets opt59 when it succeeds), so
// it is only reachable through direct construction of the unexported
// pluginState.
func TestHandler6Unconfigured(t *testing.T) {
	var p pluginState

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	gotResp, stop := p.Handler6(req, resp)
	assert.Same(t, dhcpv6.DHCPv6(resp), gotResp)
	assert.True(t, stop)
}

// TestHandler4Unconfigured exercises the opt67==nil branch of Handler4,
// which setup4 never produces (it always sets opt67 when it succeeds), so
// it is only reachable through direct construction of the unexported
// pluginState.
func TestHandler4Unconfigured(t *testing.T) {
	var p pluginState

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	gotResp, stop := p.Handler4(req, resp)
	assert.Same(t, resp, gotResp)
	assert.True(t, stop)
}
