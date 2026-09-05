// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ntp implements a plugin that serves NTP server addresses to
// DHCPv4 and DHCPv6 clients.
package ntp

import (
	"errors"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/ntp")

// Plugin wraps the NTP plugin information.
var Plugin = plugins.Plugin{
	Name:   "ntp",
	Setup6: setup6,
	Setup4: setup4,
}

type pluginState struct {
	ntpServers []net.IP
}

func setup6(args ...string) (handler.Handler6, error) {
	if len(args) < 1 {
		return nil, errors.New("need at least one NTP server")
	}
	p := pluginState{}
	for _, arg := range args {
		server := net.ParseIP(arg)
		if server == nil || server.To4() != nil {
			return nil, errors.New("expected an NTP server IPv6 address, got: " + arg)
		}
		p.ntpServers = append(p.ntpServers, server)
	}
	log.Infof("loaded %d NTP servers.", len(p.ntpServers))
	return p.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	log.Printf("loaded plugin for DHCPv4.")
	if len(args) < 1 {
		return nil, errors.New("need at least one NTP server")
	}
	p := pluginState{}
	for _, arg := range args {
		server := net.ParseIP(arg)
		if server.To4() == nil {
			return nil, errors.New("expected an NTP server IPv4 address, got: " + arg)
		}
		p.ntpServers = append(p.ntpServers, server)
	}
	log.Infof("loaded %d NTP servers.", len(p.ntpServers))
	return p.Handler4, nil
}

// Handler6 handles DHCPv6 packets for the ntp plugin.
func (p *pluginState) Handler6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	opt := dhcpv6.OptNTPServer{Suboptions: make(dhcpv6.Options, 0, len(p.ntpServers))}
	for _, server := range p.ntpServers {
		addr := dhcpv6.NTPSuboptionSrvAddr(server)
		opt.Suboptions = append(opt.Suboptions, &addr)
	}
	resp.UpdateOption(&opt)
	return resp, false
}

// Handler4 handles DHCPv4 packets for the ntp plugin.
func (p *pluginState) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	resp.Options.Update(dhcpv4.OptNTPServers(p.ntpServers...))
	return resp, false
}
