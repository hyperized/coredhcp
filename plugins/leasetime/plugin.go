// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasetime

import (
	"errors"
	"fmt"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name: "lease_time",
	// currently not supported for DHCPv6
	Setup6: nil,
	Setup4: setup4,
}

var log = logger.GetLogger("plugins/lease_time")

const msgNoLeaseTime = "no lease time given; pass a duration as the plugin argument, for example 1h"

// pluginState is the per-instance data held by the lease_time plugin.
type pluginState struct {
	leaseTime time.Duration
}

// Handler4 handles DHCPv4 packets for the lease_time plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.MessageType() == dhcpv4.MessageTypeInform {
		return resp, false
	}
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		return resp, false
	}
	// Set lease time unless it has already been set
	if !resp.Options.Has(dhcpv4.OptionIPAddressLeaseTime) {
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(p.leaseTime))
	}
	return resp, false
}

func setup4(args ...string) (handler.Handler4, error) {
	log.Print("loading `lease_time` plugin for DHCPv4")
	if len(args) < 1 {
		log.Error(msgNoLeaseTime)
		return nil, errors.New(msgNoLeaseTime)
	}

	leaseTime, err := time.ParseDuration(args[0])
	if err != nil {
		log.Errorf("lease time %q is not a duration: %v; write it the Go way, such as 1h or 3600s", args[0], err)
		return nil, fmt.Errorf("lease time %q is not a duration; write it the Go way, such as 1h or 3600s", args[0])
	}

	p := &pluginState{leaseTime: leaseTime}
	return p.Handler4, nil
}
