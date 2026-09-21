// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package staticroute

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup4(t *testing.T) {
	var err error

	// no args
	_, err = setup4()
	require.ErrorContains(t, err, "no static route given")

	// invalid arg
	_, err = setup4("foo")
	require.ErrorContains(t, err, `route "foo" is not a destination and gateway pair`)

	// invalid destination
	_, err = setup4("foo,")
	require.ErrorContains(t, err, `destination "foo" is not a CIDR subnet`)

	// invalid gateway
	_, err = setup4("10.0.0.0/8,foo")
	require.ErrorContains(t, err, `gateway "foo" is not an IPv4 address`)

	// IPv6 in either half
	_, err = setup4("2001:db8::/32,192.168.1.1")
	require.ErrorContains(t, err, `destination "2001:db8::/32" is not an IPv4 subnet`)
	_, err = setup4("10.0.0.0/8,2001:db8::1")
	require.ErrorContains(t, err, `gateway "2001:db8::1" is not an IPv4 address`)

	// valid route
	h, err := setup4("10.0.0.0/8,192.168.1.1")
	if assert.NoError(t, err) {
		assert.NotNil(t, h)
	}

	// multiple valid routes
	_, err = setup4("10.0.0.0/8,192.168.1.1", "192.168.2.0/24,192.168.1.100")
	assert.NoError(t, err)
}

// TestHandler4NoRoutes exercises the zero-routes branch of Handler4, which
// setup4 can never produce (it requires at least one valid route), so it is
// only reachable through direct construction of the unexported pluginState.
func TestHandler4NoRoutes(t *testing.T) {
	p := pluginState{routes: dhcpv4.Routes{}}

	stub := &dhcpv4.DHCPv4{}
	resp, stop := p.Handler4(nil, stub)
	assert.False(t, stop)
	assert.Nil(t, resp.Options.Get(dhcpv4.OptionClasslessStaticRoute))
}
