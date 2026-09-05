// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package subnet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Setup errors that a caller or a test can match with errors.Is. Anything
// that has to quote the offending input is built with fmt.Errorf instead, so
// the message names what was wrong with the file rather than only what rule
// it broke.
var (
	errNoSubnets       = errors.New("no subnets configured")
	errNoName          = errors.New("every subnet needs a name")
	errNoMatchRule     = errors.New("needs match.interfaces, match.relays or default: true")
	errEmptyInterface  = errors.New("empty interface name in match.interfaces")
	errNoLease         = errors.New("a subnet that hands out addresses needs a lease")
	errPoolWithoutDB   = errors.New("pool needs a leasedb to persist its leases in")
	errDBWithoutPool   = errors.New("leasedb is only used together with a pool")
	errPrefixOnV4      = errors.New("prefixpool and prefixsize are DHCPv6 only")
	errPoolOnV6        = errors.New("pool and leasedb are DHCPv4 only")
	errSizeWithoutPool = errors.New("prefixsize is only used together with a prefixpool")
	errReservationsV6  = errors.New("reservations are DHCPv4 only")
	errOptionsV4Only   = errors.New("options router, domain and ntp are DHCPv4 only")
	errMappedPrefix    = errors.New("write an IPv4 prefix in dotted-quad notation, not as IPv4-mapped IPv6")
)

// fileConfig is the whole YAML file. Decoding is strict, so a key that is not
// spelled exactly like one of these fields fails setup instead of being
// ignored: a typo in a subnet definition is the kind of mistake that would
// otherwise only show up as clients on the wrong scope.
type fileConfig struct {
	Subnets []subnetConfig `yaml:"subnets"`
}

// subnetConfig is one entry of the subnets list, straight off the disk. Every
// value is still a string here; parseSubnet turns it into a scope.
type subnetConfig struct {
	Name         string            `yaml:"name"`
	CIDR         string            `yaml:"cidr"`
	Match        matchConfig       `yaml:"match"`
	Default      bool              `yaml:"default"`
	Pool         string            `yaml:"pool"`
	PrefixPool   string            `yaml:"prefixpool"`
	PrefixSize   int               `yaml:"prefixsize"`
	Lease        string            `yaml:"lease"`
	LeaseDB      string            `yaml:"leasedb"`
	Reservations map[string]string `yaml:"reservations"`
	Options      optionsConfig     `yaml:"options"`
}

// matchConfig says which requests belong to a subnet.
type matchConfig struct {
	Interfaces []string `yaml:"interfaces"`
	Relays     []string `yaml:"relays"`
}

// optionsConfig is the small set of options a scope carries. Anything beyond
// it belongs in the options plugin, which encodes arbitrary codes.
type optionsConfig struct {
	Router string   `yaml:"router"`
	DNS    []string `yaml:"dns"`
	Domain string   `yaml:"domain"`
	NTP    []string `yaml:"ntp"`
}

// addrRange is a pool written as <start>-<end>, inclusive at both ends.
type addrRange struct {
	start, end netip.Addr
}

// String renders the range the way the configuration file writes it.
func (r addrRange) String() string { return r.start.String() + "-" + r.end.String() }

// overlaps reports whether the two ranges share an address.
func (r addrRange) overlaps(o addrRange) bool {
	return r.start.Compare(o.end) <= 0 && o.start.Compare(r.end) <= 0
}

// scope is one validated subnet: the subnet the handlers use, plus the
// arguments its range or prefix handler is built from. The two are kept apart
// because the whole file is validated on every setup while handlers are only
// built for the family being set up.
type scope struct {
	sub *subnet

	// v4 is the family of sub.cidr, which fixes which of the fields below
	// can be set at all.
	v4 bool

	// pool and leasedb are the DHCPv4 range plugin's arguments; pool is nil
	// for a subnet that allocates nothing. prefixPool and prefixSize are the
	// DHCPv6 prefix plugin's; prefixPool is invalid when unset.
	pool       *addrRange
	leasedb    string
	prefixPool netip.Prefix
	prefixSize int

	// lease is the lease duration both delegates take.
	lease time.Duration
}

// parseFile reads path and turns it into validated scopes in file order.
func parseFile(path string) ([]*scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg fileConfig
	switch err := dec.Decode(&cfg); {
	case errors.Is(err, io.EOF):
		// An empty document decodes to EOF rather than to an empty struct.
		return nil, fmt.Errorf("%s: %w", path, errNoSubnets)
	case err != nil:
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	scopes, err := compile(cfg.Subnets)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return scopes, nil
}

// compile validates every subnet on its own and then the file as a whole.
func compile(list []subnetConfig) ([]*scope, error) {
	if len(list) == 0 {
		return nil, errNoSubnets
	}
	scopes := make([]*scope, 0, len(list))
	for i, sc := range list {
		s, err := parseSubnet(sc)
		if err != nil {
			return nil, subnetError(i, sc.Name, err)
		}
		scopes = append(scopes, s)
	}
	if err := checkFile(scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

// subnetError puts the offending subnet in front of err. An entry with no
// name is identified by its position, counting from one as an operator reads
// the file.
func subnetError(idx int, name string, err error) error {
	if name == "" {
		return fmt.Errorf("subnet #%d: %w", idx+1, err)
	}
	return fmt.Errorf("subnet %q: %w", name, err)
}

// parseSubnet validates one entry and builds the scope for it. No lease
// database is opened and no allocator built here: everything in the file has
// to be checked before the first delegate handler is constructed, or a
// mistake in the last subnet leaves the earlier ones holding open files.
func parseSubnet(sc subnetConfig) (*scope, error) {
	if sc.Name == "" {
		return nil, errNoName
	}
	cidr, err := parsePrefix(sc.CIDR, "cidr")
	if err != nil {
		return nil, err
	}
	s := &scope{
		v4: cidr.Addr().Is4(),
		sub: &subnet{
			name:      sc.Name,
			cidr:      cidr,
			isDefault: sc.Default,
		},
	}
	for _, step := range []func(*scope, *subnetConfig) error{
		parseMatch, parseLease, parseAllocation, parseReservations, parseOptions,
	} {
		if err := step(s, &sc); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// parseMatch reads the selection rules. A subnet nothing can select is a
// configuration mistake, so one without rules has to say default: true.
func parseMatch(s *scope, sc *subnetConfig) error {
	if slices.Contains(sc.Match.Interfaces, "") {
		return errEmptyInterface
	}
	s.sub.ifaces = slices.Clone(sc.Match.Interfaces)
	for _, r := range sc.Match.Relays {
		p, err := parseRelay(r, s.v4)
		if err != nil {
			return err
		}
		s.sub.relays = append(s.sub.relays, p)
	}
	if len(s.sub.ifaces) == 0 && len(s.sub.relays) == 0 && !s.sub.isDefault {
		return errNoMatchRule
	}
	return nil
}

// parseRelay accepts either a single relay address or a prefix covering a
// range of them, and returns it as a prefix either way.
func parseRelay(value string, v4 bool) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		p, err := parsePrefix(value, "relay")
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4() != v4 {
			return netip.Prefix{}, familyError("relay", value, v4)
		}
		return p, nil
	}
	a, err := parseIP(value, v4, "relay")
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseLease reads the lease duration. It is required exactly for the subnets
// that hand out an address, because neither delegate has a default this
// plugin would want to inherit silently.
func parseLease(s *scope, sc *subnetConfig) error {
	if sc.Lease == "" {
		if sc.Pool != "" || sc.PrefixPool != "" || len(sc.Reservations) > 0 {
			return errNoLease
		}
		return nil
	}
	d, err := time.ParseDuration(sc.Lease)
	if err != nil {
		return fmt.Errorf("invalid lease %q: %w", sc.Lease, err)
	}
	if d <= 0 {
		return fmt.Errorf("lease %q has to be positive", sc.Lease)
	}
	s.lease = d
	s.sub.lease = d
	return nil
}

// parseAllocation reads whichever pool the subnet's family can have.
func parseAllocation(s *scope, sc *subnetConfig) error {
	if s.v4 {
		return parsePool4(s, sc)
	}
	return parsePool6(s, sc)
}

// parsePool4 reads pool and leasedb, the two arguments the range plugin needs
// beyond the lease time.
func parsePool4(s *scope, sc *subnetConfig) error {
	if sc.PrefixPool != "" || sc.PrefixSize != 0 {
		return errPrefixOnV4
	}
	if sc.Pool == "" {
		if sc.LeaseDB != "" {
			return errDBWithoutPool
		}
		return nil
	}
	if sc.LeaseDB == "" {
		return errPoolWithoutDB
	}
	r, err := parseRange(sc.Pool)
	if err != nil {
		return err
	}
	if !s.sub.cidr.Contains(r.start) || !s.sub.cidr.Contains(r.end) {
		return fmt.Errorf("pool %s is not inside %s", r, s.sub.cidr)
	}
	s.pool = &r
	s.leasedb = sc.LeaseDB
	return nil
}

// parseRange splits a <start>-<end> pool and checks the two ends are IPv4 and
// in order.
func parseRange(value string) (addrRange, error) {
	first, last, ok := strings.Cut(value, "-")
	if !ok {
		return addrRange{}, fmt.Errorf("pool %q: expected <start>-<end>", value)
	}
	start, err := parseIP(strings.TrimSpace(first), true, "pool start")
	if err != nil {
		return addrRange{}, err
	}
	end, err := parseIP(strings.TrimSpace(last), true, "pool end")
	if err != nil {
		return addrRange{}, err
	}
	if start.Compare(end) > 0 {
		return addrRange{}, fmt.Errorf("pool %q: start is above end", value)
	}
	return addrRange{start: start, end: end}, nil
}

// parsePool6 reads prefixpool and prefixsize, the prefix plugin's arguments.
// The size has to sit between the pool's own length and 128, which is the
// range of prefixes that can be carved out of it.
func parsePool6(s *scope, sc *subnetConfig) error {
	if sc.Pool != "" || sc.LeaseDB != "" {
		return errPoolOnV6
	}
	if sc.PrefixPool == "" {
		if sc.PrefixSize != 0 {
			return errSizeWithoutPool
		}
		return nil
	}
	p, err := parsePrefix(sc.PrefixPool, "prefixpool")
	if err != nil {
		return err
	}
	if p.Addr().Is4() {
		return familyError("prefixpool", sc.PrefixPool, false)
	}
	if sc.PrefixSize < p.Bits() || sc.PrefixSize > 128 {
		return fmt.Errorf("prefixsize %d has to be between %d, the prefixpool length, and 128",
			sc.PrefixSize, p.Bits())
	}
	s.prefixPool = p
	s.prefixSize = sc.PrefixSize
	return nil
}

// parseReservations canonicalizes the MAC keys and checks every address is on
// the subnet. Keys are visited in sorted order so a file with more than one
// mistake in it always fails on the same one.
func parseReservations(s *scope, sc *subnetConfig) error {
	if len(sc.Reservations) == 0 {
		return nil
	}
	if !s.v4 {
		return errReservationsV6
	}
	res := make(map[string]net.IP, len(sc.Reservations))
	for _, key := range slices.Sorted(maps.Keys(sc.Reservations)) {
		mac, err := net.ParseMAC(key)
		if err != nil {
			return fmt.Errorf("reservation %q: invalid MAC address", key)
		}
		if _, dup := res[mac.String()]; dup {
			return fmt.Errorf("reservation %q: duplicate MAC address", key)
		}
		ip, err := parseIP(sc.Reservations[key], true, "reservation "+key)
		if err != nil {
			return err
		}
		if !s.sub.cidr.Contains(ip) {
			return fmt.Errorf("reservation %q: %s is not inside %s", key, ip, s.sub.cidr)
		}
		res[mac.String()] = net.IP(ip.AsSlice())
	}
	s.sub.reservations = res
	return nil
}

// parseOptions reads the options block for the subnet's family.
func parseOptions(s *scope, sc *subnetConfig) error {
	if s.v4 {
		return parseOptions4(s, &sc.Options)
	}
	return parseOptions6(s, &sc.Options)
}

// parseOptions4 builds the DHCPv4 option set. The subnet mask is not
// configurable: it is the one option a scope always knows, straight from the
// cidr.
func parseOptions4(s *scope, o *optionsConfig) error {
	opts := options4{mask: net.CIDRMask(s.sub.cidr.Bits(), 32), domain: o.Domain}
	if o.Router != "" {
		router, err := parseIP(o.Router, true, "router")
		if err != nil {
			return err
		}
		if !s.sub.cidr.Contains(router) {
			return fmt.Errorf("router %s is not inside %s", router, s.sub.cidr)
		}
		opts.router = net.IP(router.AsSlice())
	}
	var err error
	if opts.dns, err = parseIPs(o.DNS, true, "dns"); err != nil {
		return err
	}
	if opts.ntp, err = parseIPs(o.NTP, true, "ntp"); err != nil {
		return err
	}
	s.sub.opts4 = opts
	return nil
}

// parseOptions6 builds the DHCPv6 option set, which is the resolver list and
// nothing else. Option 3 has no DHCPv6 equivalent (routers are learned from
// router advertisements), and the domain name and NTP options are encoded
// differently enough that they belong in the options and ntp plugins.
func parseOptions6(s *scope, o *optionsConfig) error {
	if o.Router != "" || o.Domain != "" || len(o.NTP) > 0 {
		return errOptionsV4Only
	}
	dns, err := parseIPs(o.DNS, false, "dns")
	if err != nil {
		return err
	}
	s.sub.dns6 = dns
	return nil
}

// checkFile runs the rules that need to see every subnet at once.
func checkFile(scopes []*scope) error {
	for _, check := range []func([]*scope) error{checkNames, checkDefaults, checkLeaseDBs, checkPools} {
		if err := check(scopes); err != nil {
			return err
		}
	}
	return nil
}

// checkNames refuses duplicate names, which would make every log line and
// every error message about them ambiguous.
func checkNames(scopes []*scope) error {
	seen := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		if seen[s.sub.name] {
			return fmt.Errorf("subnet %q: duplicate name", s.sub.name)
		}
		seen[s.sub.name] = true
	}
	return nil
}

// checkDefaults allows one fallback subnet per family. Two would make the
// fallback depend on file order, which is not something an operator should
// have to reason about.
func checkDefaults(scopes []*scope) error {
	defaults := map[bool]string{}
	for _, s := range scopes {
		if !s.sub.isDefault {
			continue
		}
		if prev, ok := defaults[s.v4]; ok {
			return fmt.Errorf("subnet %q: %s subnet %q is already the default",
				s.sub.name, familyName(s.v4), prev)
		}
		defaults[s.v4] = s.sub.name
	}
	return nil
}

// checkLeaseDBs refuses to point two subnets at one sqlite file. Sharing one
// would have two range plugins allocate from the same lease table with
// separate allocators, and hand the same address to two clients.
func checkLeaseDBs(scopes []*scope) error {
	seen := make(map[string]string, len(scopes))
	for _, s := range scopes {
		if s.leasedb == "" {
			continue
		}
		if prev, ok := seen[s.leasedb]; ok {
			return fmt.Errorf("subnet %q: leasedb %q is already used by subnet %q",
				s.sub.name, s.leasedb, prev)
		}
		seen[s.leasedb] = s.sub.name
	}
	return nil
}

// checkPools refuses overlapping pools, for the same reason as checkLeaseDBs:
// each subnet allocates from its own allocator, so an address in two pools is
// an address handed out twice.
func checkPools(scopes []*scope) error {
	for i, a := range scopes {
		for _, b := range scopes[:i] {
			if err := poolConflict(a, b); err != nil {
				return err
			}
		}
	}
	return nil
}

// poolConflict names the overlap between two scopes, if there is one.
func poolConflict(a, b *scope) error {
	switch {
	case a.pool != nil && b.pool != nil && a.pool.overlaps(*b.pool):
		return fmt.Errorf("subnet %q: pool %s overlaps the pool of subnet %q", a.sub.name, a.pool, b.sub.name)
	case a.prefixPool.IsValid() && b.prefixPool.IsValid() && a.prefixPool.Overlaps(b.prefixPool):
		return fmt.Errorf("subnet %q: prefixpool %s overlaps the prefixpool of subnet %q",
			a.sub.name, a.prefixPool, b.sub.name)
	}
	return nil
}

// parsePrefix parses a CIDR, rejecting the IPv4-mapped form because it would
// match neither family: netip.Prefix.Contains compares address lengths, so a
// ::ffff:10.0.0.0/120 scope would silently never be selected.
func parsePrefix(value, what string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid %s %q", what, value)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid %s %q: %w", what, value, errMappedPrefix)
	}
	return p.Masked(), nil
}

// parseIP parses one address and checks it is from the family the subnet
// serves. what names the field for the error message.
func parseIP(value string, v4 bool, what string) (netip.Addr, error) {
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s address %q", what, value)
	}
	a = a.Unmap()
	if a.Is4() != v4 {
		return netip.Addr{}, familyError(what, value, v4)
	}
	return a, nil
}

// parseIPs parses a list of addresses of one family, returning nil for an
// empty list so callers can tell "not configured" from "configured empty".
func parseIPs(values []string, v4 bool, what string) ([]net.IP, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		a, err := parseIP(value, v4, what)
		if err != nil {
			return nil, err
		}
		out = append(out, net.IP(a.AsSlice()))
	}
	return out, nil
}

// familyError reports a value from the wrong protocol family.
func familyError(what, value string, v4 bool) error {
	return fmt.Errorf("%s %q is not %s, which is the family of this subnet", what, value, familyName(v4))
}

// familyName spells a family out for an error message.
func familyName(v4 bool) string {
	if v4 {
		return "IPv4"
	}
	return "IPv6"
}
