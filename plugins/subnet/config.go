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

// Matched with errors.Is; an error that has to quote the offending input is
// built with fmt.Errorf instead.
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

// Decoded strictly: an unrecognized key fails setup instead of being silently
// ignored, since a typo here would otherwise only show up as clients on the wrong scope.
type fileConfig struct {
	Subnets []subnetConfig `yaml:"subnets"`
}

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

type matchConfig struct {
	Interfaces []string `yaml:"interfaces"`
	Relays     []string `yaml:"relays"`
}

// Anything beyond this set belongs in the options plugin, which encodes arbitrary codes.
type optionsConfig struct {
	Router string   `yaml:"router"`
	DNS    []string `yaml:"dns"`
	Domain string   `yaml:"domain"`
	NTP    []string `yaml:"ntp"`
}

// Inclusive at both ends.
type addrRange struct {
	start, end netip.Addr
}

// String renders the range the way the configuration file writes it.
func (r addrRange) String() string { return r.start.String() + "-" + r.end.String() }

func (r addrRange) overlaps(o addrRange) bool {
	return r.start.Compare(o.end) <= 0 && o.start.Compare(r.end) <= 0
}

// Kept apart from subnet because the whole file is validated on every setup,
// but handlers are only built for the family being set up.
type scope struct {
	sub *subnet

	// Fixes which of the fields below can be set at all.
	v4 bool

	// pool/leasedb feed the DHCPv4 range plugin, prefixPool/prefixSize the
	// DHCPv6 prefix plugin. pool is nil and prefixPool invalid when unset.
	pool       *addrRange
	leasedb    string
	prefixPool netip.Prefix
	prefixSize int

	lease time.Duration
}

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

// Counts from one, the way an operator reads the file, when the subnet has no name.
func subnetError(idx int, name string, err error) error {
	if name == "" {
		return fmt.Errorf("subnet #%d: %w", idx+1, err)
	}
	return fmt.Errorf("subnet %q: %w", name, err)
}

// No lease database opened or allocator built here: the whole file must
// validate first, or a mistake in a later subnet leaves earlier ones holding open files.
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

// A subnet nothing can select is a mistake, so one without match rules must say default: true.
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

// A bare address comes back as a single-address prefix, so callers only handle one type.
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

// Required exactly for subnets that hand out an address: neither delegate has
// a default worth inheriting silently.
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

func parseAllocation(s *scope, sc *subnetConfig) error {
	if s.v4 {
		return parsePool4(s, sc)
	}
	return parsePool6(s, sc)
}

// pool and leasedb feed the range plugin.
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

// prefixpool and prefixsize feed the prefix plugin; prefixsize must sit between
// the prefixpool's own length and 128, the range of prefixes it can carve out.
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

// Keys are visited in sorted order so a file with more than one mistake always fails on the same one.
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

func parseOptions(s *scope, sc *subnetConfig) error {
	if s.v4 {
		return parseOptions4(s, &sc.Options)
	}
	return parseOptions6(s, &sc.Options)
}

// The subnet mask isn't configurable: it's the one option a scope always knows, straight from the cidr.
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

// Router has no DHCPv6 equivalent (learned via router advertisements instead), and
// domain/NTP are encoded differently enough to belong in the options and ntp plugins.
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

func checkFile(scopes []*scope) error {
	for _, check := range []func([]*scope) error{checkNames, checkDefaults, checkLeaseDBs, checkPools} {
		if err := check(scopes); err != nil {
			return err
		}
	}
	return nil
}

// Duplicate names would make every log line and error message about them ambiguous.
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

// Two defaults per family would make the fallback depend on file order, which
// an operator shouldn't have to reason about.
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

// Sharing a leasedb would have two range plugins allocate from the same lease
// table with separate allocators, handing out the same address twice.
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

// Each subnet allocates from its own allocator, so an address in two pools would be handed out twice.
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

// Rejects the IPv4-mapped form: netip.Prefix.Contains compares address lengths,
// so a ::ffff:10.0.0.0/120 scope would silently never be selected.
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

// Returns nil for an empty list, so callers can tell not-configured from configured-empty.
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

func familyError(what, value string, v4 bool) error {
	return fmt.Errorf("%s %q is not %s, which is the family of this subnet", what, value, familyName(v4))
}

func familyName(v4 bool) string {
	if v4 {
		return "IPv4"
	}
	return "IPv6"
}
