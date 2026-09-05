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

// The raw AF_PACKET socket this needs is Linux-only. The stub keeps the
// package building, and errors only if the Ethernet path is actually taken.
func sendEthernet(_ net.Interface, _ *dhcpv4.DHCPv4) error {
	return errors.New("raw Ethernet replies are only supported on Linux")
}
