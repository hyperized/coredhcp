// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package autoconfigure implements a plugin that answers the DHCPv4
// autoconfigure option (RFC 2563) for clients that get no address.
package autoconfigure

// Place this at the end of the plugin chain, after address allocation: it only
// acts on an Offer that still carries yiaddr=0.0.0.0. The optional argument is
// "DoNotAutoConfigure" (the default, also "0") or "AutoConfigure" ("1").

import (
	"errors"
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

type pluginState struct {
	autoconfigure dhcpv4.AutoConfiguration
}

func setup4(args ...string) (handler.Handler4, error) {
	var p pluginState
	if len(args) > 0 {
		var ok bool
		p.autoconfigure, ok = argMap[args[0]]
		if !ok {
			return nil, fmt.Errorf("unexpected value '%v' for autoconfigure argument", args[0])
		}
	}
	if len(args) > 1 {
		return nil, errors.New("too many arguments")
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
	// RFC 2563 §2.3: with no address chosen, a DHCPDISCOVER without the
	// Auto-Configure option is not answered at all.
	return nil, true
}
