// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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
	"github.com/coredhcp/coredhcp/leases"
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

	// delegate is the instance behind that handler, as the leases registry
	// knows it. Nil for a subnet that allocates nothing, and for a delegate
	// whose plugin offers no way to stop it.
	delegate leases.Source
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
		return nil, fmt.Errorf("%s lists no %s subnets; add a subnet with an %s cidr, or take the subnet plugin out of this server section",
			path, familyName(v4), familyName(v4))
	}
	log.Printf("%s: serving %d subnets from %s", familyName(v4), len(s.subnets), path)
	return s, nil
}

// Close shuts down the delegates this selector built and takes them out of
// the leases registry.
//
// Nothing in the server calls it: plugins are set up once and live as long
// as the process. It is here for an embedding program, and for tests, which
// would otherwise leave a sweeper and a writer running over a lease file
// they are about to delete.
func (s *selector) Close() {
	for _, sub := range s.subnets {
		if sub.delegate == nil {
			continue
		}
		leases.Unregister(sub.delegate)
		if closer, ok := sub.delegate.(interface{ Close() }); ok {
			closer.Close()
		}
		sub.delegate = nil
	}
}

// registeredDelegate returns the instance a pool plugin registered under
// name, or nil when it registered none.
//
// Newest first, because two subnets can share a lease file and it is this
// subnet's delegate we are after.
func registeredDelegate(name string) leases.Source {
	sources := leases.Sources()
	for _, source := range slices.Backward(sources) {
		if source.Name() == name {
			return source
		}
	}
	return nil
}

// filePath picks the configuration file out of the plugin arguments.
func filePath(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("got %d arguments, want exactly one; pass %s<path>, for example %s/etc/coredhcp/subnets.yml",
			len(args), fileArgPrefix, fileArgPrefix)
	}
	path, ok := strings.CutPrefix(args[0], fileArgPrefix)
	if !ok || path == "" {
		return "", fmt.Errorf("argument %q names no file; write it as %s<path>, for example %s/etc/coredhcp/subnets.yml",
			args[0], fileArgPrefix, fileArgPrefix)
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
		sc.sub.delegate = registeredDelegate("range " + sc.leasedb)
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
