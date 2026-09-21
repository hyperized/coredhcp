// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ipv6only

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

// takesNoReply4 reports whether message type t is one the server never
// answers (RFC 2131 section 4.4). Both types carry no parameter request
// list, and dhcpv4.IsOptionRequested reads an absent list as every option
// being requested, so without this check the plugin would take a release for
// a client asking about option 108 and end the chain before the allocator
// could free the lease.
func takesNoReply4(t dhcpv4.MessageType) bool {
	return t == dhcpv4.MessageTypeRelease || t == dhcpv4.MessageTypeDecline
}

// Handler4 handles DHCPv4 packets for the ipv6only plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if takesNoReply4(req.MessageType()) {
		return resp, false
	}
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
