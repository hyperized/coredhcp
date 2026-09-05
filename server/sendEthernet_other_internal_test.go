// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build !linux

package server

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
)

// TestSendEthernetStubAlwaysErrors covers the non-Linux stub, which exists
// only so the package still compiles off Linux (see sendEthernet.go, //go:build linux).
func TestSendEthernetStubAlwaysErrors(t *testing.T) {
	err := sendEthernet(net.Interface{}, &dhcpv4.DHCPv4{})
	assert.EqualError(t, err, "raw Ethernet replies are only supported on Linux")
}
