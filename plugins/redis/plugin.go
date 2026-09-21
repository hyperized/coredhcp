// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/redis")

// Plugin wraps the redis plugin information.
var Plugin = plugins.Plugin{
	Name:   "redis",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	// Prefixes of the optional trailing arguments.
	passwordArg = "password:"
	timeoutArg  = "timeout:"
	prefixArg   = "prefix:"
	lifetimeArg = "lifetime:"
	keyArg      = "key:"

	// envPrefix marks a password that names an environment variable instead
	// of carrying the secret in the config file.
	envPrefix = "env:"

	// Defaults for the optional arguments.
	defaultPort     = "6379"
	defaultTimeout  = 2 * time.Second
	defaultLifetime = time.Hour

	// One default key prefix per key mode, so a database serving more than
	// one of them keeps the three key spaces apart.
	defaultPrefixMAC      = "mac:"
	defaultPrefixDUID     = "duid:"
	defaultPrefixClientID = "client-id:"

	// Schemes accepted in the address argument.
	schemePlain = "redis"
	schemeTLS   = "rediss"

	// Names of the hash fields this plugin understands.
	fieldIPv4      = "ipv4"
	fieldIPv6      = "ipv6"
	fieldRouter    = "router"
	fieldDNS       = "dns"
	fieldLeaseTime = "leaseTime"
)

// settings is the parsed plugin configuration.
type settings struct {
	client clientConfig
	mode   keyMode

	// prefix is only meaningful once parsing is done: it stays empty until
	// either a prefix: argument sets it, which prefixSet records, or the key
	// mode's default fills it in.
	prefix    string
	prefixSet bool

	lifetime time.Duration
}

// pluginState is one configured instance of the plugin. setup4 and setup6
// build one each, so a server that uses the plugin for both families keeps
// two independent connection pools.
type pluginState struct {
	client   *client
	prefix   string
	mode     keyMode
	lifetime time.Duration
}

func setup6(args ...string) (handler.Handler6, error) {
	p, err := setupState(true, args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	p, err := setupState(false, args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

// setupState builds the plugin instance and greets the server. See the
// package documentation for why a failed greeting is only a warning.
func setupState(v6 bool, args ...string) (*pluginState, error) {
	p, err := newPluginState(v6, args...)
	if err != nil {
		return nil, err
	}
	if err := p.client.ping(); err != nil {
		log.Warningf("redis at %s did not answer PING, starting anyway: %v; check the server is up and the password is right, lookups fail until it is",
			p.client.cfg.addr, err)
		return p, nil
	}
	log.Infof("using redis at %s, key prefix %q", p.client.cfg.addr, p.prefix)
	return p, nil
}

// newPluginState parses the arguments and builds the instance without
// touching the network. Setup goes through setupState; this is split out so
// tests can reach the client before it dials.
func newPluginState(v6 bool, args ...string) (*pluginState, error) {
	s, err := parseArgs(v6, args)
	if err != nil {
		return nil, err
	}
	return &pluginState{
		client:   newClient(s.client),
		prefix:   s.prefix,
		mode:     s.mode,
		lifetime: s.lifetime,
	}, nil
}

// optionParsers maps each optional argument to its parser. It is a fixed
// table, read only after initialization.
var optionParsers = []struct {
	prefix string
	apply  func(*settings, string) error
}{
	{passwordArg, applyPassword},
	{timeoutArg, applyTimeout},
	{prefixArg, applyPrefix},
	{lifetimeArg, applyLifetime},
	{keyArg, applyKey},
}

// parseArgs turns the config line into settings, applying the defaults first
// so an argument only ever overrides one of them. The key prefix is the
// exception: its default follows the key mode, which an argument anywhere on
// the line may have changed, so it is filled in once the line is read.
func parseArgs(v6 bool, args []string) (*settings, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("no redis address given; make the first argument host:port, or a %s:// URL, or a %s:// one for TLS", schemePlain, schemeTLS)
	}
	s := &settings{
		lifetime: defaultLifetime,
		client:   clientConfig{timeout: defaultTimeout},
	}
	if err := parseAddress(args[0], s); err != nil {
		return nil, err
	}
	for _, arg := range args[1:] {
		if err := applyOption(s, arg); err != nil {
			return nil, err
		}
	}
	if err := s.mode.checkFamily(v6); err != nil {
		return nil, err
	}
	if !s.prefixSet {
		s.prefix = s.mode.defaultPrefix()
	}
	return s, nil
}

// applyOption dispatches one optional argument to its parser.
func applyOption(s *settings, arg string) error {
	for _, o := range optionParsers {
		if raw, ok := strings.CutPrefix(arg, o.prefix); ok {
			return o.apply(s, raw)
		}
	}
	return fmt.Errorf("unknown argument %q; use one of %s %s %s %s %s, with the redis address first on the line",
		arg, passwordArg, timeoutArg, prefixArg, lifetimeArg, keyArg)
}

// applyPassword takes the password literally, or reads it from the
// environment for the env: form.
func applyPassword(s *settings, raw string) error {
	name, fromEnv := strings.CutPrefix(raw, envPrefix)
	if !fromEnv {
		if raw == "" {
			return fmt.Errorf("%s needs a value; use %s%sREDIS_PASSWORD to read it from the environment and keep it out of config.yml",
				passwordArg, passwordArg, envPrefix)
		}
		s.client.password = raw
		return nil
	}
	if name == "" {
		return fmt.Errorf("%s%s needs an environment variable name; use %s%sREDIS_PASSWORD and export it before starting coredhcp",
			passwordArg, envPrefix, passwordArg, envPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return fmt.Errorf("environment variable %s is unset or empty; export it with the redis password before starting coredhcp", name)
	}
	s.client.password = value
	return nil
}

// applyTimeout sets the dial and per-command timeout.
func applyTimeout(s *settings, raw string) error {
	d, err := parsePositiveDuration(timeoutArg, raw, defaultTimeout)
	if err != nil {
		return err
	}
	s.client.timeout = d
	return nil
}

// applyLifetime sets the DHCPv6 lifetime used when a hash has no leaseTime.
func applyLifetime(s *settings, raw string) error {
	d, err := parsePositiveDuration(lifetimeArg, raw, defaultLifetime)
	if err != nil {
		return err
	}
	s.lifetime = d
	return nil
}

// applyPrefix sets the key prefix. An empty value is allowed and means the
// keys are bare client identifiers.
func applyPrefix(s *settings, raw string) error {
	s.prefix = raw
	s.prefixSet = true
	return nil
}

// applyKey selects which client identifier the keys are built from.
func applyKey(s *settings, raw string) error {
	mode, err := parseKeyMode(raw)
	if err != nil {
		return err
	}
	s.mode = mode
	return nil
}

// parsePositiveDuration parses a Go duration and refuses anything that would
// disable the setting it configures.
func parsePositiveDuration(arg, raw string, def time.Duration) (time.Duration, error) {
	name := strings.TrimSuffix(arg, ":")
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration: %w; use a Go duration such as 2s or 1h, or leave it out for the default of %s",
			name, raw, err, def)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s %q is not positive; use a duration above zero, or leave it out for the default of %s", name, raw, def)
	}
	return d, nil
}

// parseAddress reads the first argument, either a host:port or a URL.
func parseAddress(arg string, s *settings) error {
	if !strings.Contains(arg, "://") {
		if err := validAddr(arg); err != nil {
			return err
		}
		s.client.addr = arg
		return nil
	}
	return parseURL(arg, s)
}

// parseURL reads the redis:// or rediss:// form. Parse errors are unwrapped
// down to their cause before they are reported, because net/url puts the
// whole URL in its error and the URL may carry a password.
func parseURL(arg string, s *settings) error {
	u, err := url.Parse(arg)
	if err != nil {
		if uerr, ok := errors.AsType[*url.Error](err); ok {
			err = uerr.Err
		}
		return fmt.Errorf("the redis URL does not parse: %w; write it as %s://host:port/db, or %s://host:port/db for TLS", err, schemePlain, schemeTLS)
	}
	if u.Scheme != schemePlain && u.Scheme != schemeTLS {
		return fmt.Errorf("unsupported URL scheme %q in the redis address; use %s:// for cleartext or %s:// for TLS", u.Scheme, schemePlain, schemeTLS)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("the redis URL has no host; write it as redis://host:port/db, with the host straight after the scheme")
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	if err = validPort(port); err != nil {
		return err
	}
	s.client.addr = net.JoinHostPort(host, port)
	if s.client.db, err = parseDB(u.Path); err != nil {
		return err
	}
	if u.Scheme == schemeTLS {
		// The system trust store, verified against the host from the URL.
		// There is deliberately no way to skip verification: a plugin that
		// can be told to trust anything on the network is a plugin that
		// eventually is.
		s.client.tls = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	if u.User != nil {
		s.client.username = u.User.Username()
		s.client.password, _ = u.User.Password()
	}
	return nil
}

// validAddr checks that addr is a host:port with a plausible port, so a
// mistyped address is a setup error rather than a dial failure at the first
// DHCP request.
func validAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("the redis address %q is not host:port: %w; add the port, redis listens on 6379 unless told otherwise", addr, err)
	}
	if host == "" {
		return fmt.Errorf("the redis address %q has no host; write it as host:port, for example 10.0.0.9:6379", addr)
	}
	return validPort(port)
}

// validPort refuses a port that is not a number in range. net/url only checks
// that the port of a URL is made of digits, so the range check has to happen
// here for both forms of the address.
func validPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the redis port %q is not a number from 1 to 65535; use 6379 unless the server was told to listen elsewhere", port)
	}
	return nil
}

// parseDB reads the database number from a URL path.
func parseDB(path string) (int, error) {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return 0, nil
	}
	db, err := strconv.Atoi(trimmed)
	if err != nil || db < 0 {
		return 0, fmt.Errorf("the database %q in the redis URL is not a non-negative number; use a path such as /0, or leave it off for database 0", trimmed)
	}
	return db, nil
}

// lookup reads one client's hash. ident is the canonical identifier the key
// mode built out of the request, and the Redis key is the configured prefix
// in front of it.
func (p *pluginState) lookup(ident string) (map[string]string, error) {
	key := p.prefix + ident
	fields, err := p.client.hgetall(key)
	if err != nil {
		return nil, err
	}
	for name := range fields {
		if !isKnownField(name) {
			log.Debugf("%s: ignoring unknown field %q", key, name)
		}
	}
	return fields, nil
}

// isKnownField reports whether name is a field this plugin acts on.
func isKnownField(name string) bool {
	switch name {
	case fieldIPv4, fieldIPv6, fieldRouter, fieldDNS, fieldLeaseTime:
		return true
	default:
		return false
	}
}

// addressField returns the address field for this family, logging why the
// request is being passed on when there is none.
func (p *pluginState) addressField(fields map[string]string, name, ident string) (string, bool) {
	if len(fields) == 0 {
		log.Infof("%s %s is unknown, passing", p.mode.label(), ident)
		return "", false
	}
	value, ok := fields[name]
	if !ok {
		log.Infof("%s %s has no %s field, passing", p.mode.label(), ident, name)
		return "", false
	}
	return value, true
}

// splitAddr parses either a bare address or a CIDR. bits is -1 when no prefix
// length was given.
func splitAddr(value string) (addr netip.Addr, bits int, err error) {
	if strings.Contains(value, "/") {
		pfx, prefixErr := netip.ParsePrefix(value)
		if prefixErr != nil {
			return netip.Addr{}, 0, fmt.Errorf("%q is not a CIDR address: %w; fix the field in redis, it has to look like 10.0.0.5/24", value, prefixErr)
		}
		return pfx.Addr(), pfx.Bits(), nil
	}
	addr, err = netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("%q is not an IP address: %w; fix the field in redis, it takes a bare address or a CIDR one", value, err)
	}
	// An IPv4 address written the ::ffff:a.b.c.d way is still an IPv4
	// address as far as DHCP is concerned.
	return addr.Unmap(), -1, nil
}

// parseIPv4 reads the ipv4 field. The mask is nil unless the value carried a
// prefix length.
func parseIPv4(value string) (net.IP, net.IPMask, error) {
	addr, bits, err := splitAddr(value)
	if err != nil {
		return nil, nil, err
	}
	if !addr.Is4() {
		return nil, nil, fmt.Errorf("%q is not an IPv4 address; set the %s field in redis to an IPv4 address such as 10.0.0.5/24", value, fieldIPv4)
	}
	if bits < 0 {
		return addr.AsSlice(), nil, nil
	}
	return addr.AsSlice(), net.CIDRMask(bits, 32), nil
}

// parseIPv6 reads the ipv6 field. A prefix length is accepted and dropped:
// an IA_NA hands out an address, not a subnet.
func parseIPv6(value string) (net.IP, error) {
	addr, _, err := splitAddr(value)
	if err != nil {
		return nil, err
	}
	if !addr.Is6() || addr.Is4In6() {
		return nil, fmt.Errorf("%q is not an IPv6 address; set the %s field in redis to an IPv6 address such as 2001:db8::10", value, fieldIPv6)
	}
	return addr.AsSlice(), nil
}

// dnsServers returns the entries of the dns field that belong to the wanted
// family. Entries that do not parse are skipped with a warning rather than
// failing the whole request: one typo should not cost the client its lease.
func dnsServers(value string, want4 bool) []net.IP {
	parts := strings.Split(value, ",")
	servers := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			log.Warningf("ignoring the %s entry %q, it is not an IP address; fix the field in redis, it holds a comma-separated list of addresses", fieldDNS, part)
			continue
		}
		if addr = addr.Unmap(); addr.Is4() != want4 {
			continue
		}
		servers = append(servers, addr.AsSlice())
	}
	return servers
}

// leaseTime reads the leaseTime field. A missing field and an unusable one
// are both reported as absent, so callers fall back to their default.
func leaseTime(fields map[string]string) (time.Duration, bool) {
	value, ok := fields[fieldLeaseTime]
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		log.Warningf("ignoring %s %q, it is not a duration above zero; set it in redis to a Go duration such as 12h", fieldLeaseTime, value)
		return 0, false
	}
	return d, true
}

// Handler4 handles DHCPv4 packets for the redis plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if skipsLookup4(req.MessageType()) {
		return resp, false
	}
	ident, ok := p.mode.key4(req)
	if !ok {
		return resp, false
	}
	fields, err := p.lookup(ident)
	if err != nil {
		log.Warningf("looking up %s failed, dropping the request: %v; check redis at %s is reachable and the password is right",
			ident, err, p.client.cfg.addr)
		return nil, true
	}
	value, ok := p.addressField(fields, fieldIPv4, ident)
	if !ok {
		return resp, false
	}
	addr, mask, err := parseIPv4(value)
	if err != nil {
		log.Warningf("dropping the request from %s, its redis hash is unusable: %v", ident, err)
		return nil, true
	}
	resp.YourIPAddr = addr
	if mask != nil {
		resp.Options.Update(dhcpv4.OptSubnetMask(mask))
	}
	addOptions4(req, resp, fields)
	log.Infof("%s %s given IP address %s", p.mode.label(), ident, addr)
	return resp, true
}

// skipsLookup4 reports whether mtype is a DHCPv4 message the plugin passes on
// without consulting Redis. An INFORM asks for options rather than a lease.
// A RELEASE or DECLINE gets no reply from coredhcp whatever the chain returns
// and frees no state this plugin holds, so the lookup buys nothing, while
// doing it would let anyone on the segment turn one unauthenticated packet
// into a Redis round trip, with a fresh MAC address every time.
func skipsLookup4(mtype dhcpv4.MessageType) bool {
	switch mtype {
	case dhcpv4.MessageTypeInform, dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// addOptions4 adds the router, DNS and lease time options a hash asks for.
func addOptions4(req, resp *dhcpv4.DHCPv4, fields map[string]string) {
	if value, ok := fields[fieldRouter]; ok {
		addRouter(resp, value)
	}
	if value, ok := fields[fieldDNS]; ok && req.IsOptionRequested(dhcpv4.OptionDomainNameServer) {
		if servers := dnsServers(value, true); len(servers) > 0 {
			resp.Options.Update(dhcpv4.OptDNS(servers...))
		}
	}
	if d, ok := leaseTime(fields); ok {
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(d.Round(time.Second)))
	}
}

// addRouter sets the default gateway option, skipping a value that is not a
// usable IPv4 address.
func addRouter(resp *dhcpv4.DHCPv4, value string) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		log.Warningf("ignoring %s %q, it is not an IP address; set it in redis to the IPv4 default gateway, such as 10.0.0.1", fieldRouter, value)
		return
	}
	if addr = addr.Unmap(); !addr.Is4() {
		log.Warningf("ignoring %s %q, option 3 carries an IPv4 gateway; set it in redis to an IPv4 address such as 10.0.0.1", fieldRouter, value)
		return
	}
	resp.Options.Update(dhcpv4.OptRouter(addr.AsSlice()))
}

// Handler6 handles DHCPv6 packets for the redis plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate the DHCPv6 request, dropping it: %v; please report this with the log line", err)
		return nil, true
	}
	if skipsLookup6(decap.MessageType) {
		return resp, false
	}
	iana := decap.Options.OneIANA()
	if iana == nil {
		log.Debug("No address requested")
		return resp, false
	}
	ident, ok := p.mode.key6(req, decap)
	if !ok {
		return resp, false
	}
	return p.answer6(decap, resp, iana, ident)
}

// skipsLookup6 reports whether mtype is a DHCPv6 message the plugin passes on
// without consulting Redis, for the same reason as skipsLookup4: coredhcp
// never replies to a RELEASE or DECLINE, and this plugin has no lease state
// either one could free. mtype has to be the inner message's type, not the
// outer one, because a relayed message carries the client's real type inside
// the RELAY-FORW envelope.
func skipsLookup6(mtype dhcpv6.MessageType) bool {
	switch mtype {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// answer6 is the part of Handler6 that runs once the request is known to ask
// for an address on behalf of a client we can name.
func (p *pluginState) answer6(decap *dhcpv6.Message, resp dhcpv6.DHCPv6, iana *dhcpv6.OptIANA, ident string) (dhcpv6.DHCPv6, bool) {
	fields, err := p.lookup(ident)
	if err != nil {
		log.Warningf("looking up %s failed, dropping the request: %v; check redis at %s is reachable and the password is right",
			ident, err, p.client.cfg.addr)
		return nil, true
	}
	value, ok := p.addressField(fields, fieldIPv6, ident)
	if !ok {
		return resp, false
	}
	addr, err := parseIPv6(value)
	if err != nil {
		log.Warningf("dropping the request from %s, its redis hash is unusable: %v", ident, err)
		return nil, true
	}
	lifetime := p.lifetime
	if d, ok := leaseTime(fields); ok {
		lifetime = d
	}
	resp.AddOption(&dhcpv6.OptIANA{
		IaId: iana.IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          addr,
				PreferredLifetime: lifetime,
				ValidLifetime:     lifetime,
			},
		}},
	})
	if value, ok := fields[fieldDNS]; ok && decap.IsOptionRequested(dhcpv6.OptionDNSRecursiveNameServer) {
		if servers := dnsServers(value, false); len(servers) > 0 {
			resp.UpdateOption(dhcpv6.OptDNS(servers...))
		}
	}
	log.Infof("%s %s given IP address %s", p.mode.label(), ident, addr)
	return resp, false
}
