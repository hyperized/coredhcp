// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp

import (
	"fmt"
	"net/url"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/nbp")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "nbp",
	Setup6: setup6,
	Setup4: setup4,
}

// pluginState holds the NBP options served by an instance of the nbp
// plugin.
type pluginState struct {
	opt59, opt60 dhcpv6.Option
	opt66, opt67 *dhcpv4.Option
}

func parseArgs(args ...string) (*url.URL, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("need exactly one argument, got %d; give one boot program URL, for example tftp://10.0.0.254/nbp", len(args))
	}
	u, err := url.Parse(args[0])
	if err != nil {
		return nil, fmt.Errorf("argument %q is not a URL: %w; give the boot program as a URL, for example tftp://10.0.0.254/nbp", args[0], err)
	}
	return u, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	u, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	var p pluginState
	p.opt59 = dhcpv6.OptBootFileURL(u.String())
	params := u.Query().Get("params")
	if params != "" {
		p.opt60 = &dhcpv6.OptionGeneric{
			OptionCode: dhcpv6.OptionBootfileParam,
			OptionData: []byte(params),
		}
	}
	log.Printf("loaded NBP plugin for DHCPv6.")
	return p.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	u, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}

	var p pluginState
	var otsn, obfn dhcpv4.Option
	switch u.Scheme {
	case "http", "https", "ftp":
		obfn = dhcpv4.OptBootFileName(u.String())
	default:
		otsn = dhcpv4.OptTFTPServerName(u.Host)
		obfn = dhcpv4.OptBootFileName(u.Path)
		p.opt66 = &otsn
	}

	p.opt67 = &obfn
	log.Printf("loaded NBP plugin for DHCPv4.")
	return p.Handler4, nil
}

// Handler6 handles DHCPv6 packets for the nbp plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if p.opt59 == nil {
		// nothing to do
		return resp, true
	}
	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("cannot read the client message inside the relayed request, dropping it: %v; the client will retry, check the relay that forwarded it", err)
		// drop the request, this is probably a critical error in the packet.
		return nil, true
	}
	// Contains per code rather than a loop over the ORO: a client may repeat
	// a code, and a repeat must not add the option twice.
	requested := decap.Options.RequestedOptions()
	if requested.Contains(dhcpv6.OptionBootfileURL) {
		resp.UpdateOption(p.opt59)
		log.Debugf("Added NBP %s to request", p.opt59)
	}
	if p.opt60 != nil && requested.Contains(dhcpv6.OptionBootfileParam) {
		resp.UpdateOption(p.opt60)
		log.Debugf("Added NBP %s to request", p.opt60)
	}
	return resp, true
}

// Handler4 handles DHCPv4 packets for the nbp plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if p.opt67 == nil {
		// nothing to do
		return resp, true
	}
	if req.IsOptionRequested(dhcpv4.OptionTFTPServerName) && p.opt66 != nil {
		resp.Options.Update(*p.opt66)
		log.Debugf("Added NBP %s / %s to request", p.opt66, p.opt67)
	}
	if req.IsOptionRequested(dhcpv4.OptionBootfileName) {
		resp.Options.Update(*p.opt67)
		log.Debugf("Added NBP %s to request", p.opt67)
	}
	return resp, true
}
