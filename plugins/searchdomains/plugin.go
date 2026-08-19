// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package searchdomains implements a plugin that hands out the DNS search
// list to DHCPv4 and DHCPv6 clients.
package searchdomains

// This is an searchdomains plugin that adds default DNS search domains.

import (
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/searchdomains")

// Plugin wraps the default DNS search domain options.
// Note that importing the plugin is not enough to use it: you have to
// explicitly specify the intention to use it in the `config.yml` file, in the
// plugins section. For searchdomains:
//
// server6:
//
//	listen: '[::]547'
//	- searchdomains: domain.a domain.b
//	- server_id: LL aa:bb:cc:dd:ee:ff
//	- file: "leases.txt"
var Plugin = plugins.Plugin{
	Name:   "searchdomains",
	Setup6: setup6,
	Setup4: setup4,
}

// pluginState holds the DNS search domains handed out by an instance of the
// searchdomains plugin. Note that DHCPv4 and DHCPv6 options are totally
// independent: setup6 and setup4 each build their own pluginState, so if you
// need the same settings for both, you'll need to configure this plugin once
// for the v4 and once for the v6 server.
type pluginState struct {
	searchList []string
}

// copySlice creates a new copy of a string slice in memory.
// This helps to ensure that downstream plugins can't corrupt
// this plugin's configuration
func copySlice(original []string) []string {
	copied := make([]string, len(original))
	copy(copied, original)
	return copied
}

func setup6(args ...string) (handler.Handler6, error) {
	p := pluginState{searchList: args}
	log.Printf("Registered domain search list (DHCPv6) %s", p.searchList)
	return p.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	p := pluginState{searchList: args}
	log.Printf("Registered domain search list (DHCPv4) %s", p.searchList)
	return p.Handler4, nil
}

// Handler6 handles DHCPv6 packets for the searchdomains plugin.
func (p *pluginState) Handler6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	resp.UpdateOption(dhcpv6.OptDomainSearchList(&rfc1035label.Labels{
		Labels: copySlice(p.searchList),
	}))
	return resp, false
}

// Handler4 handles DHCPv4 packets for the searchdomains plugin.
func (p *pluginState) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	resp.UpdateOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{
		Labels: copySlice(p.searchList),
	}))
	return resp, false
}
