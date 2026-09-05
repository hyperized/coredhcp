// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package subnet serves more than one scope from a single server, choosing
// the scope per request from the relay it came through, the interface it
// arrived on, or the address the client already holds.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - subnet: file:/etc/coredhcp/subnets.yml
//
// The one argument names a YAML file listing the subnets, in the order they
// are matched:
//
//	subnets:
//	  - name: office
//	    cidr: 10.0.1.0/24
//	    match:
//	      interfaces: [eth1]
//	      relays: [10.0.1.1, 10.0.9.0/24]
//	    pool: 10.0.1.100-10.0.1.200
//	    lease: 12h
//	    leasedb: /var/lib/coredhcp/office.sqlite3
//	    reservations:
//	      "aa:bb:cc:dd:ee:01": 10.0.1.5
//	    options:
//	      router: 10.0.1.1
//	      dns: [10.0.1.53, 10.0.1.54]
//	      domain: office.example
//	      ntp: [10.0.1.123]
//	  - name: guests
//	    cidr: 2001:db8:2::/48
//	    match:
//	      interfaces: [eth2]
//	    prefixpool: 2001:db8:2::/48
//	    prefixsize: 64
//	    lease: 1h
//	    options:
//	      dns: [2001:db8:2::53]
//	  - name: fallback
//	    cidr: 10.0.0.0/24
//	    default: true
//	    pool: 10.0.0.100-10.0.0.200
//	    lease: 1h
//	    leasedb: /var/lib/coredhcp/fallback.sqlite3
//	    options: {router: 10.0.0.1}
//
// A subnet's cidr fixes its family. Both families are read and validated from
// the same file, so a mistake in a DHCPv6 subnet fails a DHCPv4 server too,
// and a section whose family has no subnets in the file fails setup.
//
// Decoding is strict, and the file is read once at setup; editing it takes
// effect only on restart.
//
// # Selection
//
// For DHCPv4, the first subnet that matches one of these wins:
//
//  1. giaddr is set, and the subnet lists it in match.relays, or lists no
//     relays and has it inside its cidr.
//  2. giaddr is unset, and the subnet lists the receiving interface in
//     match.interfaces.
//  3. ciaddr, or the requested address in option 50, is inside the subnet's
//     cidr - a client renewing or rebinding from an address it already has.
//  4. The subnet marked default: true.
//
// DHCPv6 is the same without rule 3, which has no DHCPv6 equivalent, and with
// the outermost relay's link-address in place of giaddr. A relayed request is
// never matched on its interface, since that faces the relay, not the
// client's own link.
//
// A request matching nothing passes through untouched, for a later plugin to
// serve.
//
// # What a subnet answers with
//
// A selected DHCPv4 subnet sets the subnet mask and its configured router,
// DNS, domain and NTP options unconditionally, unlike the options plugin,
// since a client that omits a parameter from its request list still needs to
// be told its router and mask. A client whose MAC is in reservations gets
// that address; every other client is handed to a range plugin instance
// built for the subnet's pool, which also owns RELEASE, DECLINE and the
// lease record. INFORM gets the options and nothing else.
//
// A selected DHCPv6 subnet sets its resolvers and delegates to a prefix
// plugin instance for its prefixpool. A subnet with no prefixpool (or no v4
// pool) just sets its options and lets the chain continue - how a scope that
// only carries options is written.
//
// Each subnet gets its own range or prefix instance, with a separate
// allocator and lease database; two subnets may not share a leasedb path or
// overlap pools, since separate allocators over shared addresses would hand
// out the same address twice.
//
// # Placement
//
// subnet replaces the per-scope option plugins and the pool plugin, so list
// it instead of router, netmask, dns and range, after server_id and any
// filtering plugin. A plugin listed after it can still overwrite its
// options, since handlers run in configuration order.
//
// # Concurrency
//
// Everything is built during setup and read-only afterwards, so one loaded
// plugin serves every listener goroutine; lease state lives in the delegate
// range and prefix instances, which do their own locking.
package subnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/prefix"
	rangeplugin "github.com/coredhcp/coredhcp/plugins/range"
)

var log = logger.GetLogger("plugins/subnet")

// Plugin wraps the subnet plugin information.
var Plugin = plugins.Plugin{
	Name:      "subnet",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

// fileArgPrefix marks the plugin's only argument, as it does in macfilter.
const fileArgPrefix = "file:"

// mask is always present; the rest are set only when the file configures them.
type options4 struct {
	mask   net.IPMask
	router net.IP
	dns    []net.IP
	domain string
	ntp    []net.IP
}

func (o *options4) apply(resp *dhcpv4.DHCPv4) {
	resp.Options.Update(dhcpv4.OptSubnetMask(o.mask))
	if o.router != nil {
		resp.Options.Update(dhcpv4.OptRouter(o.router))
	}
	if len(o.dns) > 0 {
		resp.Options.Update(dhcpv4.OptDNS(o.dns...))
	}
	if o.domain != "" {
		resp.Options.Update(dhcpv4.OptDomainName(o.domain))
	}
	if len(o.ntp) > 0 {
		resp.Options.Update(dhcpv4.OptNTPServers(o.ntp...))
	}
}

// Written during setup, read-only afterwards, so handlers may run concurrently on it.
type subnet struct {
	name      string
	cidr      netip.Prefix
	ifaces    []string
	isDefault bool

	// Empty means the subnet claims relays inside its own cidr instead.
	relays []netip.Prefix

	// Only for reserved clients; the delegate sets its own lease for a pooled client.
	lease time.Duration

	opts4        options4
	dns6         []net.IP
	reservations map[string]net.IP

	// Exactly one is set; both are nil for a subnet that allocates nothing.
	handler4 handler.Handler4
	handler6 handler.Handler6
}

// Subnets are kept in file order, which is the order they're matched in.
type selector struct {
	subnets []*subnet
	def     *subnet
}

func setup4(args ...string) (handler.Handler4Ctx, error) {
	s, err := newSelector4(args...)
	if err != nil {
		return nil, err
	}
	return s.handle4, nil
}

func setup6(args ...string) (handler.Handler6Ctx, error) {
	s, err := newSelector6(args...)
	if err != nil {
		return nil, err
	}
	return s.handle6, nil
}

// setup4 wraps this; tests that want the selector itself call it directly.
func newSelector4(args ...string) (*selector, error) {
	return newSelector(true, args)
}

func newSelector6(args ...string) (*selector, error) {
	return newSelector(false, args)
}

func newSelector(v4 bool, args []string) (*selector, error) {
	path, err := filePath(args)
	if err != nil {
		return nil, err
	}
	scopes, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	s := &selector{}
	for _, sc := range scopes {
		if sc.v4 != v4 {
			continue
		}
		if err := buildDelegate(sc); err != nil {
			return nil, fmt.Errorf("%s: subnet %q: %w", path, sc.sub.name, err)
		}
		s.subnets = append(s.subnets, sc.sub)
		if sc.sub.isDefault {
			s.def = sc.sub
		}
	}
	if len(s.subnets) == 0 {
		return nil, fmt.Errorf("%s: no %s subnets configured", path, familyName(v4))
	}
	log.Printf("%s: serving %d subnets from %s", familyName(v4), len(s.subnets), path)
	return s, nil
}

func filePath(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("want exactly one argument, %s<path>, got %d", fileArgPrefix, len(args))
	}
	path, ok := strings.CutPrefix(args[0], fileArgPrefix)
	if !ok || path == "" {
		return "", fmt.Errorf("expected %s<path>, got %q", fileArgPrefix, args[0])
	}
	return path, nil
}

// A subnet with no pool gets neither, and later passes requests on unhandled.
func buildDelegate(sc *scope) error {
	switch {
	case sc.pool != nil:
		h, err := rangeplugin.Plugin.Setup4(sc.leasedb, sc.pool.start.String(), sc.pool.end.String(), sc.lease.String())
		if err != nil {
			return err
		}
		sc.sub.handler4 = h
	case sc.prefixPool.IsValid():
		h, err := prefix.Plugin.Setup6(sc.prefixPool.String(), strconv.Itoa(sc.prefixSize), sc.lease.String())
		if err != nil {
			return err
		}
		sc.sub.handler6 = h
	}
	return nil
}

func (s *selector) handle4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	sub := s.select4(ctx, req)
	if sub == nil {
		log.Debugf("no subnet matches the DHCPv4 request from %s, passing it on", req.ClientHWAddr)
		return resp, false
	}
	return sub.handle4(req, resp)
}

func (s *selector) handle6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	sub := s.select6(ctx, req)
	if sub == nil {
		log.Debug("no subnet matches this DHCPv6 request, passing it on")
		return resp, false
	}
	return sub.handle6(req, resp)
}

func (s *selector) select4(ctx context.Context, req *dhcpv4.DHCPv4) *subnet {
	if relay, ok := addrFrom(req.GatewayIPAddr); ok {
		if sub := s.byRelay(relay); sub != nil {
			return sub
		}
	} else if sub := s.byInterface(interfaceFrom(ctx)); sub != nil {
		return sub
	}
	if sub := s.byAddress(clientAddr4(req)); sub != nil {
		return sub
	}
	return s.def
}

func (s *selector) select6(ctx context.Context, req dhcpv6.DHCPv6) *subnet {
	if relay, relayed := req.(*dhcpv6.RelayMessage); relayed {
		if link, ok := addrFrom(relay.LinkAddr); ok {
			if sub := s.byRelay(link); sub != nil {
				return sub
			}
		}
	} else if sub := s.byInterface(interfaceFrom(ctx)); sub != nil {
		return sub
	}
	return s.def
}

func (s *selector) byRelay(addr netip.Addr) *subnet {
	for _, sub := range s.subnets {
		if sub.claimsRelay(addr) {
			return sub
		}
	}
	return nil
}

// An empty name matches nothing, which is what a request with no interface information looks like.
func (s *selector) byInterface(name string) *subnet {
	if name == "" {
		return nil
	}
	for _, sub := range s.subnets {
		if slices.Contains(sub.ifaces, name) {
			return sub
		}
	}
	return nil
}

func (s *selector) byAddress(addr netip.Addr) *subnet {
	if !addr.IsValid() {
		return nil
	}
	for _, sub := range s.subnets {
		if sub.cidr.Contains(addr) {
			return sub
		}
	}
	return nil
}

func (sub *subnet) claimsRelay(addr netip.Addr) bool {
	if len(sub.relays) == 0 {
		return sub.cidr.Contains(addr)
	}
	return slices.ContainsFunc(sub.relays, func(p netip.Prefix) bool { return p.Contains(addr) })
}

func (sub *subnet) handle4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mt := req.MessageType()
	if mt == dhcpv4.MessageTypeRelease || mt == dhcpv4.MessageTypeDecline {
		// RELEASE and DECLINE get no reply, but the delegate still needs to see
		// them - it owns the lease record.
		return sub.delegate4(req, resp)
	}
	sub.opts4.apply(resp)
	if mt == dhcpv4.MessageTypeInform {
		// RFC 2131 section 4.3.5: the client already has an address, so no lease is touched.
		return resp, false
	}
	if ip, ok := sub.reservations[req.ClientHWAddr.String()]; ok {
		// Cloned: resp outlives this call, and a later plugin writing into
		// YourIPAddr would otherwise edit the reservation table.
		resp.YourIPAddr = slices.Clone(ip)
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(sub.lease))
		log.Debugf("subnet %s: reserved address %s for %s", sub.name, ip, req.ClientHWAddr)
		return resp, true
	}
	return sub.delegate4(req, resp)
}

func (sub *subnet) delegate4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if sub.handler4 == nil {
		return resp, false
	}
	return sub.handler4(req, resp)
}

func (sub *subnet) handle6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if len(sub.dns6) > 0 {
		resp.UpdateOption(dhcpv6.OptDNS(sub.dns6...))
	}
	if sub.handler6 == nil {
		return resp, false
	}
	return sub.handler6(req, resp)
}

// Returns "" when the context carries no handler.RequestInfo - what a handler
// called outside the server's dispatch path sees; the zero value reads fine.
func interfaceFrom(ctx context.Context) string {
	info, _ := handler.RequestInfoFrom(ctx)
	return info.Interface
}

// Invalid when the request names neither address.
func clientAddr4(req *dhcpv4.DHCPv4) netip.Addr {
	if addr, ok := addrFrom(req.ClientIPAddr); ok {
		return addr
	}
	addr, _ := addrFrom(req.RequestedIPAddress())
	return addr
}

// False also for the unspecified address in either family - DHCP's way of saying "not set".
func addrFrom(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
