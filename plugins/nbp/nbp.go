// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package nbp implements handling of an NBP (Network Boot Program) using an
// URL, e.g. http://[fe80::abcd:efff:fe12:3456]/my-nbp or tftp://10.0.0.1/my-nbp .
// The NBP information is only added if it is requested by the client.
//
// Note that for DHCPv4, unless the URL is prefixed with a "http", "https" or
// "ftp" scheme, the URL will be split into TFTP server name (option 66)
// and Bootfile name (option 67), so the scheme will be stripped out, and it
// will be treated as a TFTP URL. Anything other than host name and file path
// will be ignored (no port, no query string, etc).
//
// For DHCPv6 OPT_BOOTFILE_URL (option 59) is used, and the value is passed
// unmodified. If the query string is specified and contains a "param" key,
// its value is also passed as OPT_BOOTFILE_PARAM (option 60), so it will be
// duplicated between option 59 and 60.
//
// Example usage:
//
// server6:
//   - plugins:
//   - nbp: http://[2001:db8:a::1]/nbp
//
// server4:
//   - plugins:
//   - nbp: tftp://10.0.0.254/nbp
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
		return nil, fmt.Errorf("exactly one argument must be passed to NBP plugin, got %d", len(args))
	}
	return url.Parse(args[0])
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
		log.Errorf("Could not decapsulate request: %v", err)
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
