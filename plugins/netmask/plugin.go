// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package netmask implements a plugin that serves the subnet mask option
// to DHCPv4 clients.
package netmask

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/netmask")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "netmask",
	Setup4: setup4,
}

// pluginState holds the netmask handed out by one setup instance of the
// plugin.
type pluginState struct {
	netmask net.IPMask
}

func setup4(args ...string) (handler.Handler4, error) {
	log.Printf("loaded plugin for DHCPv4.")
	if len(args) != 1 {
		return nil, fmt.Errorf("need exactly one netmask argument, got %d; give one dotted netmask such as 255.255.255.0", len(args))
	}
	netmaskIP := net.ParseIP(args[0])
	if netmaskIP.IsUnspecified() {
		return nil, fmt.Errorf("netmask %q is all zeroes; give a mask that covers the subnet, such as 255.255.255.0", args[0])
	}
	netmaskIP = netmaskIP.To4()
	if netmaskIP == nil {
		return nil, fmt.Errorf("netmask %q is not a dotted IPv4 mask; write it as four octets, such as 255.255.255.0", args[0])
	}
	p := pluginState{
		netmask: net.IPv4Mask(netmaskIP[0], netmaskIP[1], netmaskIP[2], netmaskIP[3]),
	}
	if !checkValidNetmask(p.netmask) {
		return nil, fmt.Errorf("netmask %q is not contiguous; use a mask whose one bits are all leading, such as 255.255.254.0", args[0])
	}
	log.Printf("loaded client netmask")
	return p.Handler4, nil
}

// Handler4 handles DHCPv4 packets for the netmask plugin
func (p *pluginState) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	resp.Options.Update(dhcpv4.OptSubnetMask(p.netmask))
	return resp, false
}

func checkValidNetmask(netmask net.IPMask) bool {
	netmaskInt := binary.BigEndian.Uint32(netmask)
	x := ^netmaskInt
	y := x + 1
	return (y & x) == 0
}
