// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package autoconfigure

import (
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/autoconfigure")

// Plugin wraps the autoconfigure plugin information.
var Plugin = plugins.Plugin{
	Name:   "autoconfigure",
	Setup4: setup4,
}

var argMap = map[string]dhcpv4.AutoConfiguration{
	"0":                  dhcpv4.AutoConfiguration(0),
	"1":                  dhcpv4.AutoConfiguration(1),
	"DoNotAutoConfigure": dhcpv4.DoNotAutoConfigure,
	"AutoConfigure":      dhcpv4.AutoConfigure,
}

// pluginState holds the configuration of an instance of the autoconfigure
// plugin.
type pluginState struct {
	autoconfigure dhcpv4.AutoConfiguration
}

func setup4(args ...string) (handler.Handler4, error) {
	var p pluginState
	if len(args) > 0 {
		var ok bool
		p.autoconfigure, ok = argMap[args[0]]
		if !ok {
			return nil, fmt.Errorf("argument %q is not an autoconfigure value; use DoNotAutoConfigure, AutoConfigure, 0 or 1, or leave it out for the default of DoNotAutoConfigure", args[0])
		}
	}
	if len(args) > 1 {
		return nil, fmt.Errorf("got %d arguments, autoconfigure takes at most one; keep the value you want and remove the rest", len(args))
	}
	return p.Handler4, nil
}

// Handler4 handles DHCPv4 packets for the autoconfigure plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if resp.MessageType() != dhcpv4.MessageTypeOffer || !resp.YourIPAddr.IsUnspecified() {
		return resp, false
	}

	ac, ok := req.AutoConfigure()
	if ok {
		resp.UpdateOption(dhcpv4.OptAutoConfigure(p.autoconfigure))
		log.With(
			"mac", req.ClientHWAddr.String(),
			"autoconfigure", fmt.Sprintf("%v", ac),
		).Debugf("Responded with autoconfigure %v", p.autoconfigure)
		return resp, false
	}

	log.With(
		"mac", req.ClientHWAddr.String(),
		"autoconfigure", "nil",
	).Debug("Client does not support autoconfigure")
	// RFC2563 2.3: if no address is chosen for the host [...]
	// If the DHCPDISCOVER does not contain the Auto-Configure option,
	// it is not answered.
	return nil, true
}
