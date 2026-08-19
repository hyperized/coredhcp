// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package staticroute

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
)

func TestSetup4(t *testing.T) {
	var err error

	// no args
	_, err = setup4()
	if assert.Error(t, err) {
		assert.Equal(t, "need at least one static route", err.Error())
	}

	// invalid arg
	_, err = setup4("foo")
	if assert.Error(t, err) {
		assert.Equal(t, "expected a destination/gateway pair, got: foo", err.Error())
	}

	// invalid destination
	_, err = setup4("foo,")
	if assert.Error(t, err) {
		assert.Equal(t, "expected a destination subnet, got: foo", err.Error())
	}

	// invalid gateway
	_, err = setup4("10.0.0.0/8,foo")
	if assert.Error(t, err) {
		assert.Equal(t, "expected a gateway address, got: foo", err.Error())
	}

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
