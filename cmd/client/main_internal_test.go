// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunBadMAC(t *testing.T) {
	err := run("not-a-mac-address", "lo")
	require.Error(t, err)
}

// Drives run() into client6.Client.Exchange, which fails on net.InterfaceByName for a
// missing interface; a real exchange needs a live server and belongs to the integration build.
func TestRunExchangeFailureNonexistentInterface(t *testing.T) {
	err := run("00:11:22:33:44:55", "nonexistent-iface-zzz-coredhcp")
	require.Error(t, err)
}

func TestPrintConversation(t *testing.T) {
	msg, err := dhcpv6.NewSolicit(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		printConversation([]dhcpv6.DHCPv6{msg})
	})
	assert.NotPanics(t, func() {
		printConversation(nil)
	})
}
