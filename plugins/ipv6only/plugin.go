// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ipv6only implements a plugin that announces the IPv6-only
// preferred option (RFC 8925) to DHCPv4 clients.
package ipv6only

// This plugin implements RFC8925: if the client has requested the
// IPv6-Only Preferred option, then add the option response and then
// terminate processing immediately.
//
// This module should be invoked *before* any IP address
// allocation has been done, so that the yiaddr is 0.0.0.0 and
// no pool addresses are consumed for compatible clients.
//
// The optional argument is the V6ONLY_WAIT configuration variable,
// described in RFC8925 section 3.2.

import (
	"fmt"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/ipv6only")

// Plugin wraps the ipv6only plugin information.
var Plugin = plugins.Plugin{
	Name:   "ipv6only",
	Setup4: setup4,
}

// pluginState holds the configuration of an instance of the ipv6only plugin.
type pluginState struct {
	v6onlyWait time.Duration
}

func setup4(args ...string) (handler.Handler4, error) {
	var p pluginState
	if len(args) > 0 {
		dur, err := time.ParseDuration(args[0])
		if err != nil {
			log.Errorf("v6only-wait %q is not a duration: %v; write it the Go way, such as 300s or 5m", args[0], err)
			return nil, fmt.Errorf("v6only-wait %q is not a duration; write it the Go way, such as 300s or 5m, or leave it out for the default of 0s", args[0])
		}
		p.v6onlyWait = dur
	}
	if len(args) > 1 {
		return nil, fmt.Errorf("got %d arguments, ipv6only takes at most one; keep the v6only-wait value and remove the rest", len(args))
	}
	return p.Handler4, nil
}

// Handler4 handles DHCPv4 packets for the ipv6only plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	v6pref := req.IsOptionRequested(dhcpv4.OptionIPv6OnlyPreferred)
	log.With(
		"mac", req.ClientHWAddr.String(),
		"ipv6only", v6pref,
	).Debug("ipv6only status")
	if v6pref {
		resp.UpdateOption(dhcpv4.OptIPv6OnlyPreferred(p.v6onlyWait))
		return resp, true
	}
	return resp, false
}
