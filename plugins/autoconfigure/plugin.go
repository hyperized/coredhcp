// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package autoconfigure implements a plugin that answers the DHCPv4
// autoconfigure option (RFC 2563) for clients that get no address.
package autoconfigure

// This plugin implements RFC2563:
// 1. If the client has been allocated an IP address, do nothing
// 2. If the client has not been allocated an IP address
//    (yiaddr=0.0.0.0), then:
//    2a. If the client has requested the "AutoConfigure" option,
//        then add the defined value to the response
//    2b. Otherwise, terminate processing and send no reply
//
// This plugin should be used at the end of the plugin chain,
// after any IP address allocation has taken place.
//
// The optional argument is the string "DoNotAutoConfigure" or
// "AutoConfigure" (or "0" or "1" respectively).  The default
// is DoNotAutoConfigure.

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
	// RFC2563 2.3: if no address is chosen for the host [...]
	// If the DHCPDISCOVER does not contain the Auto-Configure option,
	// it is not answered.
	return nil, true
}
