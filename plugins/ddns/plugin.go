// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ddns keeps DNS in step with the leases this server hands out.
//
// Every lease becomes an RFC 2136 dynamic update, signed with a TSIG key
// (RFC 8945) and sent to a name server configured to accept that key for
// the zone.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - ddns: server:10.0.0.53 zone:home.lan key:ddns-key:env:TSIG_KEY algo:hmac-sha256 ttl:300 reverse:10.0.0.0/24 timeout:2s queue:1000
//
// Arguments are key:value pairs in any order, each given once except
// reverse:, which may repeat.
//
// Required:
//
//   - server:<address> is the name server: a literal IP, not a name, with
//     an optional port, default 53.
//   - zone:<name> is the forward zone a client's name must fall under.
//   - key:<name>:<secret> is the TSIG key; secret is base64, or
//     env:<NAME> to read it from an environment variable instead.
//
// Optional:
//
//   - algo:<name> is hmac-sha256 (default), hmac-sha1 or hmac-sha512.
//   - ttl:<seconds> is the record TTL, 300 by default.
//   - reverse:<cidr> turns on PTR updates for that network; the prefix
//     must end on an octet (IPv4) or nibble (IPv6) boundary.
//   - timeout:<duration> bounds one exchange with the name server, 2s by default.
//   - queue:<n> caps updates waiting at once, 1000 by default.
//   - remove-on-release:on|off withdraws records on DHCPRELEASE, on by default.
//
// # Behaviour
//
// A lease becomes a delete-then-add of its A/AAAA records in one RFC 2136
// transaction, with a PTR update inside a configured reverse: network, and
// removed again on DHCPRELEASE. The client's name comes from the FQDN option
// (81 for DHCPv4, 39 for DHCPv6), falling back to option 12 for DHCPv4; a
// name that fails DNS syntax or the zone check is dropped, logged at debug.
//
// # Placement
//
// List the plugin after whatever assigns the address. It never answers a
// request or stops the chain, and server4/server6 each get their own queue
// and worker.
//
// # Delivery, transport and security
//
// Updates run on a background worker through a bounded queue, never on the
// packet path, over UDP with one retry. A response is trusted only once its
// TSIG verifies against the request's MAC, checked before the response code.
// Key material is never logged, nor is a secret that failed to decode.
package ddns

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/ddns")

// Plugin wraps the ddns plugin information.
var Plugin = plugins.Plugin{
	Name:   "ddns",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	serverArg  = "server:"
	zoneArg    = "zone:"
	keyArg     = "key:"
	algoArg    = "algo:"
	ttlArg     = "ttl:"
	reverseArg = "reverse:"
	timeoutArg = "timeout:"
	queueArg   = "queue:"
	removeArg  = "remove-on-release:"

	envPrefix = "env:"

	defaultPort     = "53"
	defaultAlgo     = "hmac-sha256"
	defaultTTL      = 300
	defaultTimeout  = 2 * time.Second
	defaultQueueLen = 1000

	// RFC 2181 section 8 has receivers treat a TTL with the top bit set as
	// zero, so anything above this is a typo, not a very long TTL.
	maxTTL = 1<<31 - 1

	// A misplaced digit should cost a rejected configuration, not a few
	// gigabytes of channel.
	maxQueueLen = 1 << 20

	// RFC 4702 option 81: a flags octet and two RCODE octets before the
	// name. E means the name is in wire form, N means no update wanted.
	fqdn4HeaderLen = 3
	fqdn4FlagE     = 0x04
	fqdn4FlagN     = 0x08

	// RFC 4704 option 39 has the same N flag one bit lower and no E flag:
	// its name is always in wire form.
	fqdn6FlagN = 0x04
)

// The zone is worked out once, during setup.
type reverseNet struct {
	prefix netip.Prefix
	zone   string
}

type settings struct {
	server          string
	zone            string
	key             tsigKey
	ttl             uint32
	reverse         []reverseNet
	timeout         time.Duration
	queueLen        int
	removeOnRelease bool

	// Held here until every argument is read, since the key's three parts
	// may arrive in any order.
	keyName   string
	keySecret []byte
	algo      string
}

// settings is written during setup and only read afterwards. The queue,
// counters and drop log carry the concurrency instead, each safe on its own.
type pluginState struct {
	settings

	queue    chan job
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	stats counters
	drops dropLog

	// Clock seam: set during setup, before the worker starts. timeNow falls
	// back to time.Now so a pluginState built by hand still works.
	now func() time.Time
}

func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

func setup4(args ...string) (handler.Handler4, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

func setupState(args ...string) (*pluginState, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	p.start()
	log.Infof("updating %s at %s with key %s, %d reverse zone(s)", p.zone, p.server, p.key.name, len(p.reverse))
	return p, nil
}

// Split from setupState so tests can drive the queue by hand.
func newPluginState(args ...string) (*pluginState, error) {
	s, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	return &pluginState{
		settings: *s,
		queue:    make(chan job, s.queueLen),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Fixed table, only read after initialization.
var optionParsers = []struct {
	prefix string
	apply  func(*settings, string) error
	repeat bool
}{
	{serverArg, applyServer, false},
	{zoneArg, applyZone, false},
	{keyArg, applyKey, false},
	{algoArg, applyAlgo, false},
	{ttlArg, applyTTL, false},
	{reverseArg, applyReverse, true},
	{timeoutArg, applyTimeout, false},
	{queueArg, applyQueue, false},
	{removeArg, applyRemove, false},
}

// Defaults are applied first, so an argument only ever overrides one of them.
func parseArgs(args []string) (*settings, error) {
	s := &settings{
		ttl:             defaultTTL,
		timeout:         defaultTimeout,
		queueLen:        defaultQueueLen,
		removeOnRelease: true,
		algo:            defaultAlgo,
	}
	seen := make(map[string]bool, len(args))
	for _, arg := range args {
		if err := applyOption(s, arg, seen); err != nil {
			return nil, err
		}
	}
	if err := s.finish(); err != nil {
		return nil, err
	}
	return s, nil
}

func applyOption(s *settings, arg string, seen map[string]bool) error {
	for _, o := range optionParsers {
		raw, ok := strings.CutPrefix(arg, o.prefix)
		if !ok {
			continue
		}
		if seen[o.prefix] && !o.repeat {
			return fmt.Errorf("%s given more than once", strings.TrimSuffix(o.prefix, ":"))
		}
		seen[o.prefix] = true
		return o.apply(s, raw)
	}
	return fmt.Errorf("unknown argument %q, want one of %s", arg, knownArgs())
}

func knownArgs() string {
	names := make([]string, 0, len(optionParsers))
	for _, o := range optionParsers {
		names = append(names, o.prefix+"<value>")
	}
	return strings.Join(names, " ")
}

func (s *settings) finish() error {
	switch {
	case s.server == "":
		return fmt.Errorf("%s<ip> is required", serverArg)
	case s.zone == "":
		return fmt.Errorf("%s<name> is required", zoneArg)
	case s.keyName == "":
		return fmt.Errorf("%s<name>:<secret> is required", keyArg)
	}
	key, err := newTSIGKey(s.keyName, s.algo, s.keySecret)
	if err != nil {
		return err
	}
	s.key = key
	return nil
}

func applyServer(s *settings, raw string) error {
	host, port := raw, defaultPort
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%s%s has to be an IP address, optionally followed by a port", serverArg, raw)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid port %q in %s%s", port, serverArg, raw)
	}
	s.server = netip.AddrPortFrom(addr.Unmap(), uint16(n)).String()
	return nil
}

func applyZone(s *settings, raw string) error {
	zone, err := canonicalZone(raw)
	if err != nil {
		return err
	}
	s.zone = zone
	return nil
}

// Checked against DNS name syntax, not host name syntax: it must match what
// the name server was configured with, which may use characters a host name never would.
func applyKey(s *settings, raw string) error {
	name, secret, ok := strings.Cut(raw, ":")
	if !ok || name == "" {
		return fmt.Errorf("%s needs <name>:<secret>, where the secret is base64 or %s<VARIABLE>", keyArg, envPrefix)
	}
	value, err := secretValue(secret)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("the secret of key %s is not usable base64", name)
	}
	s.keyName, s.keySecret = name, decoded
	return nil
}

func secretValue(raw string) (string, error) {
	name, fromEnv := strings.CutPrefix(raw, envPrefix)
	if !fromEnv {
		return raw, nil
	}
	if name == "" {
		return "", fmt.Errorf("%s%s needs the name of an environment variable", keyArg, envPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %s is unset or empty", name)
	}
	return value, nil
}

func applyAlgo(s *settings, raw string) error {
	if _, ok := algorithms[raw]; !ok {
		return fmt.Errorf("%w %q, want one of %v", ErrUnknownAlgorithm, raw, algorithmNames())
	}
	s.algo = raw
	return nil
}

func applyTTL(s *settings, raw string) error {
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n > maxTTL {
		return fmt.Errorf("invalid %s%s, want a number of seconds up to %d", ttlArg, raw, maxTTL)
	}
	s.ttl = uint32(n)
	return nil
}

func applyReverse(s *settings, raw string) error {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return fmt.Errorf("invalid %s%s: it has to be a CIDR", reverseArg, raw)
	}
	pfx = pfx.Masked()
	zone, err := reverseZone(pfx)
	if err != nil {
		return err
	}
	s.reverse = append(s.reverse, reverseNet{prefix: pfx, zone: zone})
	return nil
}

func applyTimeout(s *settings, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fmt.Errorf("invalid %s%s, want a positive duration such as 2s", timeoutArg, raw)
	}
	s.timeout = d
	return nil
}

func applyQueue(s *settings, raw string) error {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxQueueLen {
		return fmt.Errorf("invalid %s%s, want a number between 1 and %d", queueArg, raw, maxQueueLen)
	}
	s.queueLen = n
	return nil
}

func applyRemove(s *settings, raw string) error {
	switch raw {
	case "on":
		s.removeOnRelease = true
	case "off":
		s.removeOnRelease = false
	default:
		return fmt.Errorf("invalid %s%s, want on or off", removeArg, raw)
	}
	return nil
}

// Handler4 queues DNS updates for a lease or release; it never answers or stops the chain.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.MessageType() == dhcpv4.MessageTypeRelease {
		p.release4(req)
		return resp, false
	}
	p.lease4(req, resp)
	return resp, false
}

// Anything short of an ACK carrying an address is not a lease: an OFFER may
// never be taken up, and a NAK grants nothing.
func (p *pluginState) lease4(req, resp *dhcpv4.DHCPv4) {
	if resp == nil || resp.MessageType() != dhcpv4.MessageTypeAck {
		return
	}
	addr, ok := address4(resp.YourIPAddr)
	if !ok {
		return
	}
	name, ok := p.nameFor4(req)
	if !ok {
		return
	}
	p.enqueue(job{name: name, addrs: []netip.Addr{addr}})
}

// RFC 2131 section 4.4.6: the client names its lease in ciaddr, the only
// address in the message worth acting on.
func (p *pluginState) release4(req *dhcpv4.DHCPv4) {
	if !p.removeOnRelease {
		return
	}
	addr, ok := address4(req.ClientIPAddr)
	if !ok {
		return
	}
	name, ok := p.nameFor4(req)
	if !ok {
		return
	}
	p.enqueue(job{name: name, addrs: []netip.Addr{addr}, remove: true})
}

func (p *pluginState) nameFor4(req *dhcpv4.DHCPv4) (string, bool) {
	raw, wanted := hostname4(req)
	if !wanted {
		log.Debugf("%s asked for no DNS update", req.ClientHWAddr)
		return "", false
	}
	return p.hostFor(raw)
}

func (p *pluginState) hostFor(raw string) (string, bool) {
	name, err := hostFQDN(raw, p.zone)
	if err != nil {
		log.Debugf("not updating DNS for %q: %v", raw, err)
		return "", false
	}
	return name, true
}

// Option 81 wins over option 12: only it can say "no update". A malformed
// option 81 falls back to option 12 rather than costing the client its record.
func hostname4(req *dhcpv4.DHCPv4) (string, bool) {
	raw := req.Options.Get(dhcpv4.OptionFQDN)
	if len(raw) <= fqdn4HeaderLen {
		return req.HostName(), true
	}
	if raw[0]&fqdn4FlagN != 0 {
		return "", false
	}
	name, err := fqdnName4(raw)
	if err != nil {
		log.Debugf("option 81 from %s is malformed, falling back to the host name option: %v", req.ClientHWAddr, err)
		return req.HostName(), true
	}
	return name, true
}

// RFC 4702 option 81: the first three octets are flags and the two RCODE
// fields a server only ever echoes back.
func fqdnName4(raw []byte) (string, error) {
	body := raw[fqdn4HeaderLen:]
	if raw[0]&fqdn4FlagE == 0 {
		return string(body), nil
	}
	name, _, err := readName(body)
	return name, err
}

func address4(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip.To4())
	if !ok || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

// Handler6 is Handler4's DHCPv6 counterpart.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Debugf("could not decapsulate the request: %v", err)
		return resp, false
	}
	if msg.MessageType == dhcpv6.MessageTypeRelease {
		p.release6(msg)
		return resp, false
	}
	p.lease6(msg, resp)
	return resp, false
}

// Every IA_NA counts: a client may hold several addresses under one name,
// all belonging in the same AAAA RRset.
func (p *pluginState) lease6(req *dhcpv6.Message, resp dhcpv6.DHCPv6) {
	out, err := innerMessage(resp)
	if err != nil || out.MessageType != dhcpv6.MessageTypeReply {
		return
	}
	addrs := addresses6(out)
	if len(addrs) == 0 {
		return
	}
	name, ok := p.nameFor6(req)
	if !ok {
		return
	}
	p.enqueue(job{name: name, addrs: addrs})
}

// A Release names the addresses in its own IA_NA options; the reply to it
// carries only a status code.
func (p *pluginState) release6(req *dhcpv6.Message) {
	if !p.removeOnRelease {
		return
	}
	addrs := addresses6(req)
	if len(addrs) == 0 {
		return
	}
	name, ok := p.nameFor6(req)
	if !ok {
		return
	}
	p.enqueue(job{name: name, addrs: addrs, remove: true})
}

func (p *pluginState) nameFor6(req *dhcpv6.Message) (string, bool) {
	raw, wanted := hostname6(req)
	if !wanted {
		log.Debug("the client asked for no DNS update")
		return "", false
	}
	return p.hostFor(raw)
}

// RFC 4704 option 39 carries the name in wire form only; its N flag means
// what option 81's does.
func hostname6(msg *dhcpv6.Message) (string, bool) {
	opt := msg.Options.FQDN()
	if opt == nil || opt.DomainName == nil {
		return "", true
	}
	if opt.Flags&fqdn6FlagN != 0 {
		return "", false
	}
	return strings.Join(opt.DomainName.Labels, "."), true
}

// A relayed request's response is a relay chain that needs unwrapping.
func innerMessage(msg dhcpv6.DHCPv6) (*dhcpv6.Message, error) {
	if msg == nil {
		return nil, errors.New("there is no response to read an address from")
	}
	return msg.GetInnerMessage()
}

func addresses6(msg *dhcpv6.Message) []netip.Addr {
	var addrs []netip.Addr
	for _, iana := range msg.Options.IANA() {
		for _, ia := range iana.Options.Addresses() {
			addr, ok := address6(ia.IPv6Addr)
			if !ok {
				continue
			}
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func address6(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
