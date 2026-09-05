// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package macfilter implements a plugin that drops DHCP requests based on
// the client's hardware (MAC) address, before any other plugin acts on the
// request.
//
// The plugin takes one mode argument followed by one or more MAC sources:
//
//	server4/server6:
//	  plugins:
//	    - macfilter: allow 00:11:22:33:44:55 file:/etc/coredhcp/allowed-macs.txt
//
// The first argument selects the mode:
//
//   - allow: only requests from a listed MAC address are passed on; every
//     other request is dropped.
//   - deny: requests from a listed MAC address are dropped; every other
//     request is passed on.
//
// Every remaining argument is either a MAC address, in any format accepted
// by net.ParseMAC, or a file:/path/to/list entry naming a text file with one
// MAC address per line. Blank lines and lines starting with '#' are ignored.
// Files are read once, at setup time; they are not watched for changes. At
// least one MAC address must result, or setup fails.
//
// Matching is exact and case-insensitive: addresses are canonicalized with
// net.HardwareAddr.String() before comparison.
//
// A MAC address is not a credential -- chaddr and the DHCPv6 DUID are both
// filled in by the client -- so this keeps honest clients off a network they
// do not belong on. Authentication is what 802.1X or a separate VLAN is for.
//
// # Placement
//
// Before any plugin that allocates or reserves a lease (range, file, prefix),
// so a dropped client never touches lease state.
//
// # DHCPv6 and MAC-less requests
//
// DHCPv6 has no ClientHWAddr field, and dhcpv6.ExtractMAC can come up empty
// (a DUID-EN client behind a relay that omits the link-layer option). The two
// modes then disagree on purpose: allow drops, because a list can only pass
// what it recognizes, and deny passes, because a client with no address to
// compare cannot be on the list.
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

type pluginState struct {
	allow bool // true for allow mode, false for deny mode
	macs  map[string]struct{}
}

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

func setupState(args ...string) (*pluginState, error) {
	if len(args) < 1 {
		return nil, errors.New("need a mode argument: allow or deny")
	}

	var allow bool
	switch args[0] {
	case modeAllow:
		allow = true
	case modeDeny:
		allow = false
	default:
		return nil, fmt.Errorf("invalid mode %q, expected %q or %q", args[0], modeAllow, modeDeny)
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
			return nil, fmt.Errorf("invalid MAC address %q: %w", arg, err)
		}
		macs[hwaddr.String()] = struct{}{}
	}

	if len(macs) == 0 {
		return nil, errors.New("need at least one MAC address, directly or via a file: entry")
	}

	mode := modeDeny
	if allow {
		mode = modeAllow
	}
	log.Infof("loaded %d MAC address(es) in %s mode", len(macs), mode)

	return &pluginState{allow: allow, macs: macs}, nil
}

func loadMACFile(filename string, macs map[string]struct{}) error {
	if filename == "" {
		return errors.New("empty file path in file: entry")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}
	for i, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hwaddr, err := net.ParseMAC(line)
		if err != nil {
			return fmt.Errorf("%s:%d: invalid MAC address %q: %w", filename, i+1, line, err)
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
