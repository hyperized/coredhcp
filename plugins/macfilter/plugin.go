// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package macfilter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

const (
	modeAllow     = "allow"
	modeDeny      = "deny"
	fileArgPrefix = "file:"
)

var log = logger.GetLogger("plugins/macfilter")

// Plugin wraps the macfilter plugin information.
var Plugin = plugins.Plugin{
	Name:   "macfilter",
	Setup6: setup6,
	Setup4: setup4,
}

// pluginState holds the mode and MAC set backing one instance of the
// macfilter plugin.
type pluginState struct {
	allow bool // true for allow mode, false for deny mode
	macs  map[string]struct{}
}

// drop reports whether a request from mac should be dropped under the
// configured mode.
func (p *pluginState) drop(mac net.HardwareAddr) bool {
	_, listed := p.macs[mac.String()]
	if p.allow {
		return !listed
	}
	return listed
}

func setup6(args ...string) (handler.Handler6, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

// setupState parses the mode and MAC sources shared by setup4 and setup6.
func setupState(args ...string) (*pluginState, error) {
	if len(args) < 1 {
		return nil, errors.New("no mode given; make the first argument allow or deny, for example: macfilter: allow 00:11:22:33:44:55")
	}

	var allow bool
	switch args[0] {
	case modeAllow:
		allow = true
	case modeDeny:
		allow = false
	default:
		return nil, fmt.Errorf("mode %q is not recognised; make the first argument %q or %q", args[0], modeAllow, modeDeny)
	}

	macs := make(map[string]struct{})
	for _, arg := range args[1:] {
		if rest, ok := strings.CutPrefix(arg, fileArgPrefix); ok {
			if err := loadMACFile(rest, macs); err != nil {
				return nil, err
			}
			continue
		}
		hwaddr, err := net.ParseMAC(arg)
		if err != nil {
			return nil, fmt.Errorf("argument %q is not a MAC address: %w; write it as 00:11:22:33:44:55, or name a list file with file:/path/to/list", arg, err)
		}
		macs[hwaddr.String()] = struct{}{}
	}

	if len(macs) == 0 {
		return nil, errors.New("no MAC addresses given; list them after the mode, or name a list file with file:/path/to/list")
	}

	mode := modeDeny
	if allow {
		mode = modeAllow
	}
	log.Infof("loaded %d MAC address(es) in %s mode", len(macs), mode)

	return &pluginState{allow: allow, macs: macs}, nil
}

// loadMACFile reads one MAC address per line from filename into macs.
// Blank lines and lines starting with '#' (after leading whitespace) are
// ignored.
func loadMACFile(filename string, macs map[string]struct{}) error {
	if filename == "" {
		return errors.New("the file: entry has no path; write it as file:/path/to/list")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("cannot read the MAC list %s: %w; check that it exists and the server's user may read it", filename, err)
	}
	for i, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hwaddr, err := net.ParseMAC(line)
		if err != nil {
			return fmt.Errorf("%s:%d: %q is not a MAC address: %w; write one address per line, for example 00:11:22:33:44:55", filename, i+1, line, err)
		}
		macs[hwaddr.String()] = struct{}{}
	}
	return nil
}

// Handler4 handles DHCPv4 packets for the macfilter plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if p.drop(req.ClientHWAddr) {
		log.Infof("dropping request from MAC address %s", req.ClientHWAddr)
		return nil, true
	}
	return resp, false
}

// Handler6 handles DHCPv6 packets for the macfilter plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		if p.allow {
			log.Infof("dropping request with no extractable MAC address (allow mode fails closed): %v", err)
			return nil, true
		}
		log.Debugf("no extractable MAC address, passing in deny mode: %v", err)
		return resp, false
	}

	if p.drop(mac) {
		log.Infof("dropping request from MAC address %s", mac)
		return nil, true
	}
	return resp, false
}
