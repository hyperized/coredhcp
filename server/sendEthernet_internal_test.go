// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build linux

package server

import (
	"net"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"
)

// findMACInterface returns an interface with a hardware address, which a
// valid Ethernet header needs.
func findMACInterface(t *testing.T) net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	require.NoError(t, err)
	for _, ifi := range ifs {
		if len(ifi.HardwareAddr) == 6 {
			return ifi
		}
	}
	t.Skip("no interface with a hardware address available")
	return net.Interface{}
}

func validEthResp(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	resp, err := dhcpv4.New()
	require.NoError(t, err)
	resp.ClientHWAddr = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	resp.ServerIPAddr = net.IPv4(192, 0, 2, 1)
	resp.YourIPAddr = net.IPv4(192, 0, 2, 2)
	return resp
}

func TestSendEthernet(t *testing.T) {
	err := sendEthernet(findMACInterface(t), validEthResp(t))
	if err != nil {
		// Raw sockets need CAP_NET_RAW; skip rather than fail when the
		// environment withholds it.
		require.ErrorContains(t, err, "cannot open socket")
		t.Skipf("no raw socket privileges: %v", err)
	}
}

func TestSendEthernetNoMACSerializeFailure(t *testing.T) {
	// Loopback has no hardware address, so the Ethernet header cannot be
	// serialized.
	err := sendEthernet(net.Interface{Index: 1, Name: "lo"}, validEthResp(t))
	require.Error(t, err)
	require.ErrorContains(t, err, "cannot serialize layer")
}

func TestSendEthernetZeroValueResponse(t *testing.T) {
	// gopacket decodes even a zero-value DHCPv4, so sendEthernet's nil-layer
	// guard is defensive-only; the empty source IP fails serialization instead.
	err := sendEthernet(findMACInterface(t), &dhcpv4.DHCPv4{})
	require.Error(t, err)
	require.ErrorContains(t, err, "cannot serialize layer")
}

func TestSendEthernetBogusInterfaceIndex(t *testing.T) {
	ifi := net.Interface{
		Index:        1 << 20,
		HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1},
	}
	err := sendEthernet(ifi, validEthResp(t))
	if err == nil {
		t.Skip("kernel accepted a bogus interface index")
	}
	if strings.Contains(err.Error(), "cannot open socket") {
		// No CAP_NET_RAW (as on shared CI runners): the failure happens
		// before the frame send this test is about.
		t.Skipf("no raw socket privileges: %v", err)
	}
	require.ErrorContains(t, err, "cannot send frame via socket")
}
