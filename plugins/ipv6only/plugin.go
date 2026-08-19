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
	"errors"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/ipv6only")

var v6onlyWait time.Duration

// Plugin wraps the ipv6only plugin information.
var Plugin = plugins.Plugin{
	Name:   "ipv6only",
	Setup4: setup4,
}

func setup4(args ...string) (handler.Handler4, error) {
	if len(args) > 0 {
		dur, err := time.ParseDuration(args[0])
		if err != nil {
			log.Errorf("invalid duration: %v", args[0])
			return nil, errors.New("ipv6only failed to initialize")
		}
		v6onlyWait = dur
	}
	if len(args) > 1 {
		return nil, errors.New("too many arguments")
	}
	return Handler4, nil
}

// Handler4 handles DHCPv4 packets for the ipv6only plugin.
func Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	v6pref := req.IsOptionRequested(dhcpv4.OptionIPv6OnlyPreferred)
	log.With(
		"mac", req.ClientHWAddr.String(),
		"ipv6only", v6pref,
	).Debug("ipv6only status")
	if v6pref {
		resp.UpdateOption(dhcpv4.OptIPv6OnlyPreferred(v6onlyWait))
		return resp, true
	}
	return resp, false
}
