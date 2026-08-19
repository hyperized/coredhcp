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
//	    - redis: 10.0.0.9:6379 password:env:REDIS_PASSWORD timeout:2s prefix:mac: lifetime:1h
//
// The first argument is the server address. It is either a plain host:port,
// or a URL: redis://[user[:password]@]host[:port][/db] for a cleartext
// connection and rediss://... for TLS. A URL without a port uses 6379, and
// the path selects the database number. TLS verifies the server against the
// system trust store using the host from the URL; there is no switch to turn
// that off.
//
// The remaining arguments are optional and may appear in any order. An
// argument that is not one of these fails setup by name:
//
//   - password:<value> or password:env:<NAME> overrides any password in the
//     URL. The env: form reads the variable once, during setup, and fails if
//     it is unset or empty. Passwords are never logged, and neither is the
//     userinfo part of the URL.
//   - timeout:<duration> bounds the dial, the TLS handshake and every
//     command. It defaults to 2s and has to be positive.
//   - prefix:<key-prefix> is put in front of the MAC address to build the key.
//     It defaults to "mac:". An empty prefix means the key is the bare MAC.
//   - lifetime:<duration> is the DHCPv6 preferred and valid lifetime used for
//     clients whose hash carries no leaseTime. It defaults to 1h.
//
// # Data model
//
// One hash per client, keyed by <prefix><mac>, with the MAC written the way
// net.HardwareAddr.String() writes it: lowercase hex, colon separated.
//
//	HSET mac:aa:bb:cc:dd:ee:ff ipv4 10.0.0.5/24 router 10.0.0.1 dns 10.0.0.2,10.0.0.3 leaseTime 12h
//
// The fields this plugin reads:
//
//   - ipv4: the address handed to a DHCPv4 client, bare (10.0.0.5) or in CIDR
//     notation (10.0.0.5/24). The CIDR form also sets the subnet mask option.
//   - ipv6: the address handed to a DHCPv6 client, bare or in CIDR notation.
//     A prefix length is accepted and ignored, because an IA_NA carries an
//     address and no mask.
//   - router: the IPv4 default gateway, option 3.
//   - dns: resolver addresses, comma separated. Both families may be listed
//     in the same field; the DHCPv4 handler uses the IPv4 entries and the
//     DHCPv6 handler the IPv6 ones. Like the dedicated dns plugin, the option
//     is only added when the client asked for it. For DHCPv4 that includes a
//     client that sent no parameter request list at all, which RFC 2131
//     section 3.5 reads as asking for everything available.
//   - leaseTime: a Go duration such as 12h or 3600s. It becomes the DHCPv4
//     lease time option and the DHCPv6 address lifetimes.
//
// Any other field is ignored, with a line in the debug log naming it.
//
// # Behaviour
//
// Setup sends one PING. A failure there is logged as a warning naming the
// address and the error, so a wrong password or a typo in the address shows
// up at startup, but it does not fail setup: a DHCP server that refuses to
// start because a database is briefly down is worse than one that starts and
// serves its other plugins while the database comes back.
//
// At request time the two failure modes are deliberately different. A client
// that Redis does not know, or knows without an address for this family, is
// passed on so a later plugin such as range can serve it. A lookup that fails
// because Redis is unreachable, refuses the credentials, or answers something
// unparseable drops the request instead: a client with a documented static
// address must not silently fall through to a dynamic pool because the
// backend hiccuped, and a dropped DHCP request is retried moments later.
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

	// envPrefix marks a password that names an environment variable instead
	// of carrying the secret in the config file.
	envPrefix = "env:"

	// Defaults for the optional arguments.
	defaultPort     = "6379"
	defaultTimeout  = 2 * time.Second
	defaultPrefix   = "mac:"
	defaultLifetime = time.Hour

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
	client   clientConfig
	prefix   string
	lifetime time.Duration
}

// pluginState is one configured instance of the plugin. setup4 and setup6
// build one each, so a server that uses the plugin for both families keeps
// two independent connection pools.
type pluginState struct {
	client   *client
	prefix   string
	lifetime time.Duration
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

// setupState builds the plugin instance and greets the server. See the
// package documentation for why a failed greeting is only a warning.
func setupState(args ...string) (*pluginState, error) {
	p, err := newPluginState(args...)
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

// newPluginState parses the arguments and builds the instance without
// touching the network. Setup goes through setupState; this is split out so
// tests can reach the client before it dials.
func newPluginState(args ...string) (*pluginState, error) {
	s, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	return &pluginState{
		client:   newClient(s.client),
		prefix:   s.prefix,
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
}

// parseArgs turns the config line into settings, applying the defaults first
// so an argument only ever overrides one of them.
func parseArgs(args []string) (*settings, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("need a redis address, either host:port or a %s:// or %s:// URL", schemePlain, schemeTLS)
	}
	s := &settings{
		prefix:   defaultPrefix,
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
	return s, nil
}

// applyOption dispatches one optional argument to its parser.
func applyOption(s *settings, arg string) error {
	for _, o := range optionParsers {
		if raw, ok := strings.CutPrefix(arg, o.prefix); ok {
			return o.apply(s, raw)
		}
	}
	return fmt.Errorf("unknown argument %q, want one of %s%s%s%s<value>",
		arg, passwordArg, timeoutArg, prefixArg, lifetimeArg)
}

// applyPassword takes the password literally, or reads it from the
// environment for the env: form.
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

// applyTimeout sets the dial and per-command timeout.
func applyTimeout(s *settings, raw string) error {
	d, err := parsePositiveDuration(timeoutArg, raw)
	if err != nil {
		return err
	}
	s.client.timeout = d
	return nil
}

// applyLifetime sets the DHCPv6 lifetime used when a hash has no leaseTime.
func applyLifetime(s *settings, raw string) error {
	d, err := parsePositiveDuration(lifetimeArg, raw)
	if err != nil {
		return err
	}
	s.lifetime = d
	return nil
}

// applyPrefix sets the key prefix. An empty value is allowed and means the
// keys are bare MAC addresses.
func applyPrefix(s *settings, raw string) error {
	s.prefix = raw
	return nil
}

// parsePositiveDuration parses a Go duration and refuses anything that would
// disable the setting it configures.
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
		return fmt.Errorf("invalid redis address %q, want host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("invalid redis address %q, it has no host", addr)
	}
	return validPort(port)
}

// validPort refuses a port that is not a number in range. net/url only checks
// that the port of a URL is made of digits, so the range check has to happen
// here for both forms of the address.
func validPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid redis port %q", port)
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
		return 0, fmt.Errorf("invalid database %q in redis URL, want a non-negative number", trimmed)
	}
	return db, nil
}

// lookup reads one client's hash.
func (p *pluginState) lookup(mac net.HardwareAddr) (map[string]string, error) {
	key := p.prefix + mac.String()
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
func addressField(fields map[string]string, name string, mac net.HardwareAddr) (string, bool) {
	if len(fields) == 0 {
		log.Infof("MAC address %s is unknown, passing", mac)
		return "", false
	}
	value, ok := fields[name]
	if !ok {
		log.Infof("MAC address %s has no %s field, passing", mac, name)
		return "", false
	}
	return value, true
}

// splitAddr parses either a bare address or a CIDR. bits is -1 when no prefix
// length was given.
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
		return nil, nil, fmt.Errorf("%q is not an IPv4 address", value)
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
		return nil, fmt.Errorf("%q is not an IPv6 address", value)
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

// leaseTime reads the leaseTime field. A missing field and an unusable one
// are both reported as absent, so callers fall back to their default.
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
	if req.MessageType() == dhcpv4.MessageTypeInform {
		return resp, false
	}
	mac := req.ClientHWAddr
	fields, err := p.lookup(mac)
	if err != nil {
		log.Warningf("looking up %s failed, dropping the request: %v", mac, err)
		return nil, true
	}
	value, ok := addressField(fields, fieldIPv4, mac)
	if !ok {
		return resp, false
	}
	addr, mask, err := parseIPv4(value)
	if err != nil {
		log.Warningf("dropping the request from %s: %v", mac, err)
		return nil, true
	}
	resp.YourIPAddr = addr
	if mask != nil {
		resp.Options.Update(dhcpv4.OptSubnetMask(mask))
	}
	addOptions4(req, resp, fields)
	log.Infof("MAC address %s given IP address %s", mac, addr)
	return resp, true
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
	iana := decap.Options.OneIANA()
	if iana == nil {
		log.Debug("No address requested")
		return resp, false
	}
	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		log.Infof("Could not find client MAC for %s, passing", req)
		return resp, false
	}
	return p.answer6(decap, resp, iana, mac)
}

// answer6 is the part of Handler6 that runs once the request is known to ask
// for an address on behalf of a MAC address we can name.
func (p *pluginState) answer6(decap *dhcpv6.Message, resp dhcpv6.DHCPv6, iana *dhcpv6.OptIANA, mac net.HardwareAddr) (dhcpv6.DHCPv6, bool) {
	fields, err := p.lookup(mac)
	if err != nil {
		log.Warningf("looking up %s failed, dropping the request: %v", mac, err)
		return nil, true
	}
	value, ok := addressField(fields, fieldIPv6, mac)
	if !ok {
		return resp, false
	}
	addr, err := parseIPv6(value)
	if err != nil {
		log.Warningf("dropping the request from %s: %v", mac, err)
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
	log.Infof("MAC address %s given IP address %s", mac, addr)
	return resp, false
}
