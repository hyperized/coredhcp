// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package redis implements a plugin that reads per-client DHCP settings from
// a Redis server, so leases can be handed out from a database that other
// systems write to while coredhcp is running.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - redis: 10.0.0.9:6379 password:env:REDIS_PASSWORD timeout:2s prefix:mac: lifetime:1h key:mac
//
// The first argument is the server address: a plain host:port, or a URL
// redis://[user[:password]@]host[:port][/db] (rediss:// for TLS). A URL
// without a port uses 6379 and the path selects the database number. TLS
// verifies against the system trust store, with no switch to turn that off.
//
// The remaining arguments are optional and may appear in any order. An
// argument that is not one of these fails setup by name:
//
//   - password:<value> or password:env:<NAME> overrides any password in the
//     URL. The env: form reads the variable once, during setup.
//   - timeout:<duration> bounds the dial, the TLS handshake and every
//     command. Defaults to 2s, has to be positive.
//   - prefix:<key-prefix> goes in front of the client identifier. Defaults to
//     the key mode's own prefix; empty means a bare identifier.
//   - lifetime:<duration> is the DHCPv6 lifetime for clients whose hash
//     carries no leaseTime. Defaults to 1h.
//   - key:<mac|duid|client-id> selects the identifier the keys are built
//     from. Defaults to mac.
//
// # Data model
//
// One hash per client, keyed by <prefix><identifier>.
//
// key:mac works for both families. The MAC is written the way
// net.HardwareAddr.String() writes it, and the prefix defaults to "mac:".
//
//	HSET mac:aa:bb:cc:dd:ee:ff ipv4 10.0.0.5/24 router 10.0.0.1 dns 10.0.0.2,10.0.0.3 leaseTime 12h
//
// key:duid is server6 only, for clients whose DUID-EN or DUID-UUID carries no
// link-layer address to key a MAC on. The key is the DUID as it goes on the
// wire, two-octet type code included, in lowercase hex with no separators,
// behind the default prefix "duid:". At most 130 octets: RFC 8415 section
// 11.1 caps a DUID at 128 and the type code is two more.
//
//	HSET duid:00030001aabbccddeeff ipv6 2001:db8::10:1 leaseTime 12h
//
// key:client-id is server4 only: the raw bytes of option 61 in lowercase hex,
// behind the default prefix "client-id:". RFC 2132 section 9.14 puts a type
// octet first, type 1 being a hardware address and type 255 an RFC 4361 DUID.
//
//	HSET client-id:01aabbccddeeff ipv4 10.0.0.5/24
//
// The fields this plugin reads:
//
//   - ipv4: the DHCPv4 address, bare (10.0.0.5) or CIDR (10.0.0.5/24). The
//     CIDR form also sets the subnet mask option.
//   - ipv6: the DHCPv6 address, bare or CIDR. A prefix length is accepted and
//     ignored: an IA_NA carries an address and no mask.
//   - router: the IPv4 default gateway, option 3.
//   - dns: resolver addresses, comma separated. Both families may share the
//     field; each handler picks its own. Added only when the client asked for
//     it, which for DHCPv4 includes a client that sent no parameter request
//     list at all (RFC 2131 section 3.5).
//   - leaseTime: a Go duration such as 12h. Becomes the DHCPv4 lease time
//     option and the DHCPv6 address lifetimes.
//
// Any other field is ignored, with a line in the debug log naming it.
//
// # Behaviour
//
// A failed PING at setup is a warning, not an error: a server that will not
// start because a database is briefly down is worse than one that starts and
// serves its other plugins. At request time an unknown client is passed on so
// a later plugin such as range can serve it, but a lookup that fails drops
// the request rather than letting a documented static address fall through to
// a dynamic pool. RELEASE and DECLINE skip the lookup: nothing replies to
// them and this plugin holds no lease state, so a lookup would only give an
// unauthenticated sender a Redis round trip per forged MAC.
//
// # Placement
//
// For DHCPv4 the plugin answers the request, so list it after the plugins
// whose options should still apply and before any dynamic pool.
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

	// Marks a password that names an environment variable instead of carrying
	// the secret in the config file.
	envPrefix = "env:"

	// Defaults for the optional arguments.
	defaultPort     = "6379"
	defaultTimeout  = 2 * time.Second
	defaultLifetime = time.Hour

	// One per key mode, so a database serving more than one keeps the three
	// key spaces apart.
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

type settings struct {
	client clientConfig
	mode   keyMode

	// Empty until a prefix: argument sets it, which prefixSet records, or the
	// key mode's default fills it in once the whole line is read.
	prefix    string
	prefixSet bool

	lifetime time.Duration
}

// setup4 and setup6 build one each, so serving both families keeps two
// independent connection pools.
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

// See the package documentation for why a failed PING is only a warning.
func setupState(v6 bool, args ...string) (*pluginState, error) {
	p, err := newPluginState(v6, args...)
	if err != nil {
		return nil, err
	}
	if err := p.client.ping(); err != nil {
		log.Warningf("redis at %s did not answer PING, continuing anyway: %v", p.client.cfg.addr, err)
		return p, nil
	}
	log.Infof("using redis at %s, key prefix %q", p.client.cfg.addr, p.prefix)
	return p, nil
}

// Split out from setupState so tests can reach the client before it dials.
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

// The key prefix default follows the key mode, which an argument anywhere on
// the line may change, so it is filled in only once the line has been read.
func parseArgs(v6 bool, args []string) (*settings, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("need a redis address, either host:port or a %s:// or %s:// URL", schemePlain, schemeTLS)
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

func applyOption(s *settings, arg string) error {
	for _, o := range optionParsers {
		if raw, ok := strings.CutPrefix(arg, o.prefix); ok {
			return o.apply(s, raw)
		}
	}
	return fmt.Errorf("unknown argument %q, want one of %s %s %s %s %s",
		arg, passwordArg, timeoutArg, prefixArg, lifetimeArg, keyArg)
}

func applyPassword(s *settings, raw string) error {
	name, fromEnv := strings.CutPrefix(raw, envPrefix)
	if !fromEnv {
		if raw == "" {
			return fmt.Errorf("%s needs a value", passwordArg)
		}
		s.client.password = raw
		return nil
	}
	if name == "" {
		return fmt.Errorf("%s%s needs an environment variable name", passwordArg, envPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return fmt.Errorf("environment variable %s is unset or empty", name)
	}
	s.client.password = value
	return nil
}

func applyTimeout(s *settings, raw string) error {
	d, err := parsePositiveDuration(timeoutArg, raw)
	if err != nil {
		return err
	}
	s.client.timeout = d
	return nil
}

func applyLifetime(s *settings, raw string) error {
	d, err := parsePositiveDuration(lifetimeArg, raw)
	if err != nil {
		return err
	}
	s.lifetime = d
	return nil
}

// An empty value is allowed and means the keys are bare client identifiers.
func applyPrefix(s *settings, raw string) error {
	s.prefix = raw
	s.prefixSet = true
	return nil
}

func applyKey(s *settings, raw string) error {
	mode, err := parseKeyMode(raw)
	if err != nil {
		return err
	}
	s.mode = mode
	return nil
}

func parsePositiveDuration(arg, raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s%s: %w", arg, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s has to be positive, got %s", strings.TrimSuffix(arg, ":"), raw)
	}
	return d, nil
}

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

// Parse errors are unwrapped down to their cause before being reported:
// net/url puts the whole URL in its error, and the URL may carry a password.
func parseURL(arg string, s *settings) error {
	u, err := url.Parse(arg)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("invalid redis URL: %w", err)
	}
	if u.Scheme != schemePlain && u.Scheme != schemeTLS {
		return fmt.Errorf("unsupported URL scheme %q, want %s:// or %s://", u.Scheme, schemePlain, schemeTLS)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("redis URL has no host")
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	if err := validPort(port); err != nil {
		return err
	}
	s.client.addr = net.JoinHostPort(host, port)
	if s.client.db, err = parseDB(u.Path); err != nil {
		return err
	}
	if u.Scheme == schemeTLS {
		// No way to skip verification: a plugin that can be told to trust
		// anything on the network is a plugin that eventually is.
		s.client.tls = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	if u.User != nil {
		s.client.username = u.User.Username()
		s.client.password, _ = u.User.Password()
	}
	return nil
}

// A mistyped address is a setup error rather than a dial failure at the first
// DHCP request.
func validAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid redis address %q, want host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("invalid redis address %q, it has no host", addr)
	}
	return validPort(port)
}

// net/url only checks that a URL's port is digits, so the range check has to
// happen here for both forms of the address.
func validPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid redis port %q", port)
	}
	return nil
}

func parseDB(path string) (int, error) {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return 0, nil
	}
	db, err := strconv.Atoi(trimmed)
	if err != nil || db < 0 {
		return 0, fmt.Errorf("invalid database %q in redis URL, want a non-negative number", trimmed)
	}
	return db, nil
}

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

func isKnownField(name string) bool {
	switch name {
	case fieldIPv4, fieldIPv6, fieldRouter, fieldDNS, fieldLeaseTime:
		return true
	default:
		return false
	}
}

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

// bits is -1 when no prefix length was given.
func splitAddr(value string) (addr netip.Addr, bits int, err error) {
	if strings.Contains(value, "/") {
		pfx, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return pfx.Addr(), pfx.Bits(), nil
	}
	addr, err = netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("invalid address %q: %w", value, err)
	}
	// ::ffff:a.b.c.d is still an IPv4 address as far as DHCP is concerned.
	return addr.Unmap(), -1, nil
}

// The mask is nil unless the value carried a prefix length.
func parseIPv4(value string) (net.IP, net.IPMask, error) {
	addr, bits, err := splitAddr(value)
	if err != nil {
		return nil, nil, err
	}
	if !addr.Is4() {
		return nil, nil, fmt.Errorf("%q is not an IPv4 address", value)
	}
	if bits < 0 {
		return addr.AsSlice(), nil, nil
	}
	return addr.AsSlice(), net.CIDRMask(bits, 32), nil
}

// A prefix length is accepted and dropped: an IA_NA hands out an address, not
// a subnet.
func parseIPv6(value string) (net.IP, error) {
	addr, _, err := splitAddr(value)
	if err != nil {
		return nil, err
	}
	if !addr.Is6() || addr.Is4In6() {
		return nil, fmt.Errorf("%q is not an IPv6 address", value)
	}
	return addr.AsSlice(), nil
}

// An entry that does not parse is skipped with a warning: one typo should not
// cost the client its lease.
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
			log.Warningf("ignoring invalid %s entry %q", fieldDNS, part)
			continue
		}
		if addr = addr.Unmap(); addr.Is4() != want4 {
			continue
		}
		servers = append(servers, addr.AsSlice())
	}
	return servers
}

// A missing field and an unusable one both read as absent, so callers fall
// back to their default.
func leaseTime(fields map[string]string) (time.Duration, bool) {
	value, ok := fields[fieldLeaseTime]
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		log.Warningf("ignoring invalid %s %q", fieldLeaseTime, value)
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
		log.Warningf("looking up %s failed, dropping the request: %v", ident, err)
		return nil, true
	}
	value, ok := p.addressField(fields, fieldIPv4, ident)
	if !ok {
		return resp, false
	}
	addr, mask, err := parseIPv4(value)
	if err != nil {
		log.Warningf("dropping the request from %s: %v", ident, err)
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

// An INFORM asks for options rather than a lease. A RELEASE or DECLINE gets
// no reply and frees no state here, so a lookup would only let anyone on the
// segment turn one unauthenticated packet into a Redis round trip.
func skipsLookup4(mtype dhcpv4.MessageType) bool {
	switch mtype {
	case dhcpv4.MessageTypeInform, dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
}

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

func addRouter(resp *dhcpv4.DHCPv4, value string) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		log.Warningf("ignoring invalid %s %q", fieldRouter, value)
		return
	}
	if addr = addr.Unmap(); !addr.Is4() {
		log.Warningf("ignoring %s %q, it is not an IPv4 address", fieldRouter, value)
		return
	}
	resp.Options.Update(dhcpv4.OptRouter(addr.AsSlice()))
}

// Handler6 handles DHCPv6 packets for the redis plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate: %v", err)
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

// Same reasoning as skipsLookup4. mtype has to be the inner message's type: a
// relayed message carries the client's real type inside the RELAY-FORW.
func skipsLookup6(mtype dhcpv6.MessageType) bool {
	switch mtype {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

func (p *pluginState) answer6(decap *dhcpv6.Message, resp dhcpv6.DHCPv6, iana *dhcpv6.OptIANA, ident string) (dhcpv6.DHCPv6, bool) {
	fields, err := p.lookup(ident)
	if err != nil {
		log.Warningf("looking up %s failed, dropping the request: %v", ident, err)
		return nil, true
	}
	value, ok := p.addressField(fields, fieldIPv6, ident)
	if !ok {
		return resp, false
	}
	addr, err := parseIPv6(value)
	if err != nil {
		log.Warningf("dropping the request from %s: %v", ident, err)
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
