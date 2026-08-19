// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build !linux

package server

import (
	"errors"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// sendEthernet requires a raw AF_PACKET socket to unicast a response to a
// client that does not have an IP address yet, which only exists on Linux.
// Everywhere else the server falls back to this stub so the package still
// compiles; callers get an error at runtime if the Ethernet path is selected.
func sendEthernet(_ net.Interface, _ *dhcpv4.DHCPv4) error {
	return errors.New("raw Ethernet replies are only supported on Linux")
}
