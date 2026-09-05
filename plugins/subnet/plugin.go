// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package subnet implements a plugin that serves more than one scope from a
// single server, choosing the scope per request from the relay the request
// came through, the interface it arrived on, or the address the client
// already holds.
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
// A subnet's cidr fixes its family, and the server4 and server6 sections each
// only see the subnets of their own. Both families are read from the same
// file, and both validate all of it, so a mistake in a DHCPv6 subnet fails a
// DHCPv4 server too. A section whose family has no subnets in the file fails
// setup rather than loading a plugin that could never match.
//
// Decoding is strict: a key that is not one of these fails setup by name. The
// file is read once, during setup. Editing it has no effect until the server
// is restarted.
//
// # Selection
//
// For DHCPv4, the first subnet that matches one of these wins:
//
//  1. giaddr is set, and the subnet lists the address in match.relays, or
//     lists no relays at all and has it inside its cidr.
//  2. giaddr is unset, and the subnet lists the receiving interface in
//     match.interfaces. The interface comes from the request context, so it
//     is only known for a plugin the server dispatches with one.
//  3. ciaddr, or the requested address in option 50, is inside the subnet's
//     cidr. This is what catches a client renewing or rebinding from an
//     address it already has.
//  4. The subnet marked default: true.
//
// DHCPv6 is the same list without rule 3, which has no DHCPv6 equivalent, and
// with the outermost relay's link-address in place of giaddr. A relayed
// request is never matched on its interface: it arrives on the interface
// facing the relay, which says nothing about the link the client is on.
//
// A request that matches nothing passes through untouched, with a line in the
// debug log, so a later plugin can still serve it.
//
// # What a subnet answers with
//
// A selected DHCPv4 subnet sets the subnet mask from its cidr, and the
// router, DNS, domain name and NTP options it configures. They are set
// unconditionally rather than only when the client asks for them, as the
// options plugin does, because a client that leaves a parameter out of its
// request list still has to be told which router and mask its link uses.
//
// The address then comes from one of two places. A client whose MAC is in
// reservations gets that address and ends the chain. Every other client is
// handed to a range plugin instance built for this subnet's pool, and
// whatever it answers is what this plugin answers. RELEASE and DECLINE go
// straight to that same instance, which owns the lease record; the server
// sends no reply to either. INFORM gets the options and nothing else.
//
// A selected DHCPv6 subnet sets its resolvers and then delegates to a prefix
// plugin instance for its prefixpool. A subnet without a prefixpool, or a
// DHCPv4 subnet without a pool, sets its options and lets the chain continue,
// which is how a scope that only carries options is written.
//
// Each subnet gets a range or prefix instance of its own, with a separate
// allocator and lease database. Two subnets may not share a leasedb
// path or overlap pools: separate allocators over shared addresses hand the
// same address to two clients.
//
// # Placement
//
// subnet replaces the per-scope option plugins and the pool plugin, so list
// it instead of router, netmask, dns and range, after server_id and any
// filtering plugin. Options set by a plugin listed after it still win, since
// handlers run in configuration order and each overwrites what came before.
//
// # Concurrency
//
// Everything is built during setup and only read afterwards, so one loaded
// plugin serves every listener goroutine. The lease state behind it lives in
// the delegate range and prefix instances, which do their own locking.
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

// Plugin wraps the subnet plugin information. Both families are
// context-aware: the interface a request arrived on is the only thing that
// identifies the link of a client that is not behind a relay, and it exists
// nowhere in the packet.
var Plugin = plugins.Plugin{
	Name:      "subnet",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

// fileArgPrefix marks the plugin's only argument, as it does in macfilter.
const fileArgPrefix = "file:"

// options4 is the DHCPv4 option set of one subnet. mask is always present,
// the rest are set only when the file configures them.
type options4 struct {
	mask   net.IPMask
	router net.IP
	dns    []net.IP
	domain string
	ntp    []net.IP
}

// apply writes the subnet's options into resp, overwriting whatever an
// earlier plugin put there.
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

// subnet is one scope as the handlers see it: what selects it, what it
// answers with, and the delegate that allocates for it. It is written during
// setup and read-only afterwards.
type subnet struct {
	name      string
	cidr      netip.Prefix
	ifaces    []string
	isDefault bool

	// relays are the relay addresses this subnet claims, each as a prefix.
	// An empty list means the subnet claims the relays inside its cidr.
	relays []netip.Prefix

	// lease is what a reserved client is told to hold its address for. The
	// delegate sets its own for a pooled client.
	lease time.Duration

	opts4        options4
	dns6         []net.IP
	reservations map[string]net.IP

	// handler4 and handler6 are the range and prefix instances built for this
	// subnet's pool. Exactly one can be set, and both are nil for a subnet
	// that allocates nothing.
	handler4 handler.Handler4
	handler6 handler.Handler6
}

// selector holds one family's subnets in file order, which is the order they
// are matched in.
type selector struct {
	subnets []*subnet
	def     *subnet
}

// setup4 is the DHCPv4 setup function, implementing plugins.SetupFunc4Ctx.
func setup4(args ...string) (handler.Handler4Ctx, error) {
	s, err := newSelector4(args...)
	if err != nil {
		return nil, err
	}
	return s.handle4, nil
}

// setup6 is the DHCPv6 setup function, implementing plugins.SetupFunc6Ctx.
func setup6(args ...string) (handler.Handler6Ctx, error) {
	s, err := newSelector6(args...)
	if err != nil {
		return nil, err
	}
	return s.handle6, nil
}

// newSelector4 loads the file and builds the DHCPv4 selector. setup4 wraps it;
// tests that want the selector itself call this.
func newSelector4(args ...string) (*selector, error) {
	return newSelector(true, args)
}

// newSelector6 is newSelector4 for DHCPv6.
func newSelector6(args ...string) (*selector, error) {
	return newSelector(false, args)
}

// newSelector loads the configured file, keeps the subnets of one family and
// builds a delegate handler for each.
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

// filePath picks the configuration file out of the plugin arguments.
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

// buildDelegate constructs the range or prefix instance this subnet allocates
// from. A subnet with no pool gets neither and passes requests on.
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

// handle4 implements handler.Handler4Ctx.
func (s *selector) handle4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	sub := s.select4(ctx, req)
	if sub == nil {
		log.Debugf("no subnet matches the DHCPv4 request from %s, passing it on", req.ClientHWAddr)
		return resp, false
	}
	return sub.handle4(req, resp)
}

// handle6 implements handler.Handler6Ctx.
func (s *selector) handle6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	sub := s.select6(ctx, req)
	if sub == nil {
		log.Debug("no subnet matches this DHCPv6 request, passing it on")
		return resp, false
	}
	return sub.handle6(req, resp)
}

// select4 picks the subnet a DHCPv4 request belongs to, or nil.
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

// select6 picks the subnet a DHCPv6 request belongs to, or nil.
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

// byRelay returns the first subnet claiming the relay at addr.
func (s *selector) byRelay(addr netip.Addr) *subnet {
	for _, sub := range s.subnets {
		if sub.claimsRelay(addr) {
			return sub
		}
	}
	return nil
}

// byInterface returns the first subnet listing name. An empty name matches
// nothing, which is what a request with no interface information gets.
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

// byAddress returns the first subnet whose cidr holds addr.
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

// claimsRelay reports whether a request relayed by addr belongs to this
// subnet. A subnet that lists no relays claims the ones on its own link,
// which is how a relay running on the scope's gateway is usually addressed.
func (sub *subnet) claimsRelay(addr netip.Addr) bool {
	if len(sub.relays) == 0 {
		return sub.cidr.Contains(addr)
	}
	return slices.ContainsFunc(sub.relays, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// handle4 answers a DHCPv4 request from this subnet.
func (sub *subnet) handle4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mt := req.MessageType()
	if mt == dhcpv4.MessageTypeRelease || mt == dhcpv4.MessageTypeDecline {
		// Neither is answered, so options and reservations would go nowhere.
		// The delegate still has to see them: it owns the lease record.
		return sub.delegate4(req, resp)
	}
	sub.opts4.apply(resp)
	if mt == dhcpv4.MessageTypeInform {
		// RFC 2131 section 4.3.5: the client already has an address and is
		// asking for parameters only, so no lease is touched.
		return resp, false
	}
	if ip, ok := sub.reservations[req.ClientHWAddr.String()]; ok {
		// Cloned because resp outlives this call and a later plugin is free
		// to write into YourIPAddr, which would edit the reservation table.
		resp.YourIPAddr = slices.Clone(ip)
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(sub.lease))
		log.Debugf("subnet %s: reserved address %s for %s", sub.name, ip, req.ClientHWAddr)
		return resp, true
	}
	return sub.delegate4(req, resp)
}

// delegate4 hands the request to this subnet's range instance, or passes it
// on when the subnet has no pool.
func (sub *subnet) delegate4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if sub.handler4 == nil {
		return resp, false
	}
	return sub.handler4(req, resp)
}

// handle6 answers a DHCPv6 request from this subnet.
func (sub *subnet) handle6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if len(sub.dns6) > 0 {
		resp.UpdateOption(dhcpv6.OptDNS(sub.dns6...))
	}
	if sub.handler6 == nil {
		return resp, false
	}
	return sub.handler6(req, resp)
}

// interfaceFrom returns the interface a request arrived on, or "" when the
// context carries no handler.RequestInfo. That is what a handler called
// outside the server's dispatch path sees, and the zero value reads fine.
func interfaceFrom(ctx context.Context) string {
	info, _ := handler.RequestInfoFrom(ctx)
	return info.Interface
}

// clientAddr4 returns the address a client says it already has: ciaddr, or
// the requested address in option 50 when ciaddr is unset. The result is
// invalid when the request names neither.
func clientAddr4(req *dhcpv4.DHCPv4) netip.Addr {
	if addr, ok := addrFrom(req.ClientIPAddr); ok {
		return addr
	}
	addr, _ := addrFrom(req.RequestedIPAddress())
	return addr
}

// addrFrom converts a net.IP into a netip.Addr, reporting false for the
// values DHCP uses to mean "not set": a missing or malformed address, and the
// unspecified address in either family.
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
