// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package handler_test

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"

	"github.com/coredhcp/coredhcp/handler"
)

// TestHandlerTypes is a compile-time and shape check that Handler4 and
// Handler6 accept and return the packet types every plugin relies on. The
// package declares only these two function types, so there is no other
// behaviour to exercise.
func TestHandlerTypes(t *testing.T) {
	var h4 handler.Handler4 = func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		return resp, false
	}
	var h6 handler.Handler6 = func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		return resp, false
	}

	resp4, stop4 := h4(nil, nil)
	assert.Nil(t, resp4)
	assert.False(t, stop4)

	resp6, stop6 := h6(nil, nil)
	assert.Nil(t, resp6)
	assert.False(t, stop6)
}
