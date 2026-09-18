// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ddns keeps DNS in step with the leases this server hands out.
//
// Every lease it sees becomes an RFC 2136 dynamic update, signed with a TSIG
// key (RFC 8945) and sent to a name server that has been configured to accept
// that key for the zone. Kea has had this for years and dnsmasq still has
// nothing like it, which is why coredhcp was asked for it in upstream issue
// #92 back in 2020.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - ddns: server:10.0.0.53 zone:home.lan key:ddns-key:env:TSIG_KEY algo:hmac-sha256 ttl:300 reverse:10.0.0.0/24 protect:gateway,ns timeout:2s queue:1000
//
// Arguments are key:value pairs in any order. Each may be given once, except
// reverse: and protect:, which may be repeated.
//
// Three are required:
//
//   - server:<address> is the name server to send updates to, as an IP
//     address with an optional port that defaults to 53. It has to be a
//     literal address, not a name: a DHCP server that looks up its DNS
//     server's name through the resolver it is feeding has a bootstrap
//     problem the first time the two disagree.
//   - zone:<name> is the forward zone. A client that sends a bare host name
//     gets it appended to this zone; one that sends a fully qualified name
//     has to send a name under this zone or nothing is written.
//   - key:<name>:<secret> is the TSIG key, where <name> is the key name the
//     server knows it by and <secret> is base64. The env:<NAME> form reads
//     the base64 from an environment variable instead, which is how a secret
//     stays out of the configuration file. The variable is read once, during
//     setup. Key material is never logged, and neither is a secret that
//     failed to decode.
//
// The rest are optional:
//
//   - algo:<name> is one of hmac-sha256 (the default), hmac-sha1 or
//     hmac-sha512, and has to match what the name server has for the key.
//   - ttl:<seconds> is the TTL of the records written, 300 by default.
//   - reverse:<cidr> turns on PTR updates for addresses inside that network.
//     The prefix length has to end on a label boundary of its .arpa tree:
//     a multiple of 8 for IPv4, a multiple of 4 for IPv6. Anything else has
//     no reverse zone of its own, and this plugin will not guess at an RFC
//     2317 delegation.
//   - timeout:<duration> bounds one exchange with the name server. It
//     defaults to 2s.
//   - queue:<n> is how many updates may be waiting at once, 1000 by default.
//   - remove-on-release:on|off decides whether a DHCPRELEASE withdraws the
//     records again. It defaults to on.
//   - protect:<name>[,<name>...] names hosts this plugin will never write,
//     in either direction. A bare label is taken as a name under the zone; a
//     fully qualified one has to sit under it. Use it for names that have to
//     keep meaning what they mean, such as gateway, vpn or ns.
//
// # Behaviour
//
// A DHCPv4 ACK with an address and a usable host name, or a DHCPv6 Reply with
// addresses and an FQDN option, becomes one message: delete every A (or AAAA)
// record at the name, add the lease, and add the DHCID that says whose name
// it now is. They travel in a single update section, which RFC 2136 applies
// as one transaction, so a client that moves to a new address never has two
// records at once. When the address falls inside a reverse: network, a
// second message replaces the PTR in that zone. A DHCPRELEASE takes the
// records away again.
//
// The name a client asks for is the FQDN option -- 81 for DHCPv4, 39 for
// DHCPv6 -- and falls back to option 12 for DHCPv4. Both FQDN options have a
// flag with which a client says it wants no update at all, and that is
// honoured. A name only reaches the zone after it has been lowercased and
// checked: labels of 1 to 63 characters from [a-z0-9-], no leading or
// trailing hyphen, nothing over 253 octets, and the whole name under the
// configured zone. Every packet field here is written by whoever is on the
// segment, so a name that does not pass is dropped with a line in the debug
// log rather than being cleaned up and written anyway.
//
// # Who holds a name
//
// Every name this plugin writes carries a DHCID record (RFC 4701) that
// identifies the client it was written for, and every update is sent under
// the prerequisites of RFC 4703 section 5.3, so a laptop calling itself vpn
// is refused by the name server instead of taking vpn.<zone> from whatever
// was there.
//
// A name that carries no DHCID is held by nobody, and the first client to
// ask for it gets it. That covers records an operator wrote by hand and
// records this plugin itself wrote before it started sending DHCIDs, which
// is worth knowing when upgrading. protect: is how a name is kept out of
// reach of that.
//
// A DHCID is not a secret either: it is a digest of a hardware address or a
// DUID, both of which travel in the clear, so anyone watching the segment
// can put another client's identity in a packet. What this rules out is a
// client taking a name under its own identity; a forged one is a link-layer
// problem, for port security or DHCP snooping.
//
// # Releases
//
// A DHCPRELEASE is not authenticated and is never answered. This instance
// keeps a register in memory of the names it wrote, for which client and at
// which addresses, and a release that does not match it is dropped on the
// packet path with nothing sent. What gets past that is sent as a delete
// under the prerequisite that the DHCID at the name is still the releasing
// client's.
//
// The register does not survive a restart, and it is bounded, so it forgets
// the oldest names once it is full. A release naming a name it has forgotten
// is ignored until the client renews, which leaves a record standing for at
// most one lease time. That is the deliberate direction to fail in: a record
// that lingers costs less than a name anyone can delete by asking.
//
// # Placement
//
// List the plugin after whatever assigns the address, since it reads the
// address out of the response being built. It never answers a request and
// never stops the chain, so nothing after it is affected by where it sits.
//
// The server sends nothing back for a DHCPRELEASE, but it does run the chain
// for one, which is how the withdrawal gets seen.
//
// # Delivery
//
// Updates never happen on the packet path. Each handler drops a job into a
// bounded queue that one worker goroutine drains; when the queue is full the
// job is dropped, counted, and complained about at most once a minute. A DNS
// server that has gone slow must not slow down the DHCP server in front of
// it: a lease handed out a second late is worse than a record that is a
// minute stale.
//
// Listing the plugin under both server4 and server6 builds two instances,
// each with its own queue and worker. They are independent, as two entries in
// the configuration should be.
//
// # Transport
//
// Updates go over UDP and nothing else. The messages are a few hundred octets
// and the answers smaller still, so the truncation the TCP fallback exists
// for does not arise; if a server does set the TC bit anyway, the update is
// logged and counted rather than retried over TCP. One retry covers a lost
// datagram, and past that the client's next renewal will queue the update
// again.
//
// A response is only believed once its TSIG verifies against the MAC of the
// request. The response code is read after that, never before: a spoofed
// REFUSED that is taken at face value turns into a record that silently never
// appears.
//
// One consequence is worth knowing about. A name server asked about a zone it
// does not hold has no key to sign the refusal with, so it answers NOTAUTH
// unsigned; Knot and BIND both do. That reaches the log as an unsigned
// response naming the code it claimed, rather than as a plain NOTAUTH, which
// is the honest reading: the answer may equally have come from anyone on the
// path. Either way the fix is at the name server.
package ddns

import (
	"context"
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
	// Argument prefixes.
	serverArg  = "server:"
	zoneArg    = "zone:"
	keyArg     = "key:"
	algoArg    = "algo:"
	ttlArg     = "ttl:"
	reverseArg = "reverse:"
	timeoutArg = "timeout:"
	queueArg   = "queue:"
	removeArg  = "remove-on-release:"
	protectArg = "protect:"

	// envPrefix marks a secret that names an environment variable instead of
	// carrying the key material in the configuration file.
	envPrefix = "env:"

	// Defaults for the optional arguments.
	defaultPort     = "53"
	defaultAlgo     = "hmac-sha256"
	defaultTTL      = 300
	defaultTimeout  = 2 * time.Second
	defaultQueueLen = 1000

	// maxTTL is the largest TTL that means what it says. RFC 2181 section 8
	// has receivers treat anything with the top bit set as zero, so a value
	// above this is a typo rather than a very long TTL.
	maxTTL = 1<<31 - 1

	// maxQueueLen caps queue: so a misplaced digit costs a rejected
	// configuration instead of a few gigabytes of channel.
	maxQueueLen = 1 << 20

	// The RFC 4702 option 81 layout: a flags octet and two RCODE octets in
	// front of the name. E says the name is in DNS wire form rather than
	// ASCII, N says the client wants no update at all.
	fqdn4HeaderLen = 3
	fqdn4FlagE     = 0x04
	fqdn4FlagN     = 0x08

	// RFC 4704 option 39 has the same N flag one bit lower, and no E flag:
	// its name is always in wire form.
	fqdn6FlagN = 0x04
)

// reverseNet is one configured reverse: network and the zone it maps to,
// worked out once during setup.
type reverseNet struct {
	prefix netip.Prefix
	zone   string
}

// settings is the parsed configuration of one instance.
type settings struct {
	server          string
	zone            string
	key             tsigKey
	ttl             uint32
	reverse         []reverseNet
	timeout         time.Duration
	queueLen        int
	removeOnRelease bool
	protect         map[string]bool

	// The key is built from three arguments that may arrive in any order, so
	// its parts are held here until every argument has been read. The same
	// goes for protect:, whose names are only resolvable once the zone is
	// known.
	keyName    string
	keySecret  []byte
	algo       string
	protectRaw []string
}

// pluginState is one configured instance of the plugin.
//
// Everything in settings is written during setup and only read afterwards.
// The queue, the counters and the drop log carry the concurrency: handlers on
// several listener goroutines write to them while the worker reads, and each
// is safe for that on its own.
type pluginState struct {
	settings

	queue    chan job
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	// ctx is this instance's lifetime rather than one update's, because the
	// plugin API hands a handler no context of the instance's lifetime, only
	// one per request. Cancelling it lets a dial or a retry in flight give up
	// instead of running its own timeout out first.
	//nolint:containedctx // scoped to the instance, not to a request
	ctx    context.Context
	cancel context.CancelFunc

	// owners is the register of names this instance wrote, which is what a
	// DHCPRELEASE is weighed against before anything is sent.
	owners *owners

	stats counters
	drops dropLog

	// now is the clock seam. It is set during setup, before the worker
	// starts, and only read afterwards; timeNow falls back to time.Now so a
	// pluginState built by hand still works.
	now func() time.Time
}

// timeNow reads the clock through the seam.
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

// setupState builds an instance and starts its worker.
func setupState(args ...string) (*pluginState, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	p.start()
	log.Infof("updating %s at %s with key %s, %d reverse zone(s)", p.zone, p.server, p.key.name, len(p.reverse))
	return p, nil
}

// newPluginState parses the arguments and builds the instance without
// starting anything. Setup goes through setupState; this is split out so
// tests can drive the queue by hand.
func newPluginState(args ...string) (*pluginState, error) {
	s, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &pluginState{
		settings: *s,
		queue:    make(chan job, s.queueLen),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		owners:   newOwners(maxOwners),
	}, nil
}

// optionParsers maps each argument to its parser. It is a fixed table, only
// read after initialization.
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
	{protectArg, applyProtect, true},
}

// parseArgs turns the configuration line into settings, applying the defaults
// first so an argument only ever overrides one of them.
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

// applyOption dispatches one argument to its parser, refusing a second copy
// of anything but reverse:.
func applyOption(s *settings, arg string, seen map[string]bool) error {
	for _, o := range optionParsers {
		raw, ok := strings.CutPrefix(arg, o.prefix)
		if !ok {
			continue
		}
		if seen[o.prefix] && !o.repeat {
			return fmt.Errorf("%s is given more than once; keep one and remove the rest", strings.TrimSuffix(o.prefix, ":"))
		}
		seen[o.prefix] = true
		return o.apply(s, raw)
	}
	return fmt.Errorf("argument %q is not one this plugin takes; use one of %s", arg, knownArgs())
}

// knownArgs lists the argument prefixes for an error message.
func knownArgs() string {
	names := make([]string, 0, len(optionParsers))
	for _, o := range optionParsers {
		names = append(names, o.prefix+"<value>")
	}
	return strings.Join(names, " ")
}

// finish fills in what the arguments imply and refuses a configuration that
// cannot work.
func (s *settings) finish() error {
	switch {
	case s.server == "":
		return fmt.Errorf("%s<ip> is missing; add the name server to send updates to, for example %s10.0.0.53", serverArg, serverArg)
	case s.zone == "":
		return fmt.Errorf("%s<name> is missing; add the forward zone to write into, for example %shome.lan", zoneArg, zoneArg)
	case s.keyName == "":
		return fmt.Errorf("%s<name>:<secret> is missing; add the TSIG key the name server knows, for example %sddns-key:%sTSIG_KEY",
			keyArg, keyArg, envPrefix)
	}
	key, err := newTSIGKey(s.keyName, s.algo, s.keySecret)
	if err != nil {
		return err
	}
	s.key = key
	s.protect, err = protectedNames(s.protectRaw, s.zone)
	return err
}

// protectedNames resolves the protect: arguments against the zone, which is
// only known once every argument has been read.
func protectedNames(raw []string, zone string) (map[string]bool, error) {
	if len(raw) == 0 {
		return nil, nil //nolint:nilnil // a nil map is the empty set of protected names
	}
	out := make(map[string]bool, len(raw))
	for _, entry := range raw {
		name, err := hostFQDN(entry, zone)
		if err != nil {
			return nil, fmt.Errorf("%s%s is not a name this plugin can protect: %w; use a bare label or a name under the zone", protectArg, entry, err)
		}
		out[name] = true
	}
	return out, nil
}

// applyServer parses the name server address.
func applyServer(s *settings, raw string) error {
	host, port := raw, defaultPort
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%s%s is not an IP address; write a literal address with an optional port, such as %s10.0.0.53:5353", serverArg, raw, serverArg)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("port %q in %s%s is not a port number; use 1 to 65535, or leave the port off for the default of %s", port, serverArg, raw, defaultPort)
	}
	s.server = netip.AddrPortFrom(addr.Unmap(), uint16(n)).String()
	return nil
}

// applyZone parses the forward zone.
func applyZone(s *settings, raw string) error {
	zone, err := canonicalZone(raw)
	if err != nil {
		return err
	}
	s.zone = zone
	return nil
}

// applyKey parses key:<name>:<secret>.
//
// The name is taken as the operator wrote it and checked only for what a DNS
// name has to be, because it has to match what the name server was configured
// with and DNS labels are allowed to hold characters a host name never would.
// Neither the secret nor a value that failed to decode ever reaches an error
// message.
func applyKey(s *settings, raw string) error {
	name, secret, ok := strings.Cut(raw, ":")
	if !ok || name == "" {
		return fmt.Errorf("%s needs <name>:<secret>; give the secret as base64 or as %s<VARIABLE>, for example %sddns-key:%sTSIG_KEY",
			keyArg, envPrefix, keyArg, envPrefix)
	}
	value, err := secretValue(secret)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("the secret of key %s is not usable base64; copy the secret as the name server's key configuration spells it", name)
	}
	s.keyName, s.keySecret = name, decoded
	return nil
}

// secretValue returns the base64 secret, reading it from the environment for
// the env: form.
func secretValue(raw string) (string, error) {
	name, fromEnv := strings.CutPrefix(raw, envPrefix)
	if !fromEnv {
		return raw, nil
	}
	if name == "" {
		return "", fmt.Errorf("%s%s names no environment variable; write it as %s<VARIABLE>, for example %sTSIG_KEY", keyArg, envPrefix, envPrefix, envPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %s is unset or empty; set it to the key's base64 secret in the server's environment", name)
	}
	return value, nil
}

// applyAlgo picks the TSIG algorithm.
func applyAlgo(s *settings, raw string) error {
	if _, ok := algorithms[raw]; !ok {
		return fmt.Errorf("%w %q; use one of %v, whichever the name server has for this key", ErrUnknownAlgorithm, raw, algorithmNames())
	}
	s.algo = raw
	return nil
}

// applyTTL parses the TTL of the records written.
func applyTTL(s *settings, raw string) error {
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n > maxTTL {
		return fmt.Errorf("%s%s is not a TTL; use a number of seconds up to %d, or leave it out for the default of %d", ttlArg, raw, maxTTL, defaultTTL)
	}
	s.ttl = uint32(n)
	return nil
}

// applyReverse adds one reverse network and works out the zone it maps to.
func applyReverse(s *settings, raw string) error {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return fmt.Errorf("%s%s is not a CIDR; write it as <prefix>/<length>, such as %s10.0.0.0/24", reverseArg, raw, reverseArg)
	}
	pfx = pfx.Masked()
	zone, err := reverseZone(pfx)
	if err != nil {
		return err
	}
	s.reverse = append(s.reverse, reverseNet{prefix: pfx, zone: zone})
	return nil
}

// applyTimeout bounds one exchange with the name server.
func applyTimeout(s *settings, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fmt.Errorf("%s%s is not a positive duration; use a Go duration such as 2s, or leave it out for the default of %s", timeoutArg, raw, defaultTimeout)
	}
	s.timeout = d
	return nil
}

// applyQueue sets how many updates may be waiting at once.
func applyQueue(s *settings, raw string) error {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxQueueLen {
		return fmt.Errorf("%s%s is not a queue length; use a number between 1 and %d, or leave it out for the default of %d", queueArg, raw, maxQueueLen, defaultQueueLen)
	}
	s.queueLen = n
	return nil
}

// applyProtect adds names this plugin will never write. They are checked
// against the zone in finish, once it is known; here a stray comma is a typo
// worth refusing rather than a name worth guessing at.
func applyProtect(s *settings, raw string) error {
	for name := range strings.SplitSeq(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("%s%s holds an empty name; write one name or several separated by commas, such as %sgateway,ns", protectArg, raw, protectArg)
		}
		s.protectRaw = append(s.protectRaw, name)
	}
	return nil
}

// applyRemove decides whether a release withdraws the records.
func applyRemove(s *settings, raw string) error {
	switch raw {
	case "on":
		s.removeOnRelease = true
	case "off":
		s.removeOnRelease = false
	default:
		return fmt.Errorf("%s%s is neither on nor off; use %son or %soff, or leave it out for the default of on", removeArg, raw, removeArg, removeArg)
	}
	return nil
}

// Handler4 queues the DNS records for a lease the chain has just granted, or
// withdraws them on a release. It never answers a request and never stops the
// chain.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.MessageType() == dhcpv4.MessageTypeRelease {
		p.release4(req)
		return resp, false
	}
	p.lease4(req, resp)
	return resp, false
}

// lease4 queues the records for a granted lease. Anything short of an ACK
// carrying an address is not a lease: an OFFER may never be taken up, and a
// NAK grants nothing.
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
	p.claim(name, []netip.Addr{addr}, identity4(req))
}

// release4 withdraws the records of a lease a client is giving up. RFC 2131
// section 4.4.6 has the client name that lease in ciaddr, which is the only
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
	p.withdraw(name, []netip.Addr{addr}, identity4(req))
}

// claim queues the records for a lease, under the DHCID that says whose
// name it is.
func (p *pluginState) claim(name string, addrs []netip.Addr, id identity) {
	dhcid, err := id.record(name)
	if err != nil {
		log.Debugf("not updating DNS for %s: %v", name, err)
		return
	}
	p.enqueue(job{name: name, addrs: addrs, dhcid: dhcid})
}

// withdraw queues the removal of a lease's records, and only for the client
// this instance wrote them for.
//
// Nothing in a DHCPRELEASE is authenticated, so the register decides and not
// the packet. See the owners type for what a restart does to that.
func (p *pluginState) withdraw(name string, addrs []netip.Addr, id identity) {
	dhcid, err := id.record(name)
	if err != nil {
		log.Debugf("not withdrawing DNS for %s: %v", name, err)
		return
	}
	if !p.owners.holds(name, dhcid, addrs) {
		log.Debugf("ignoring a release of %s at %v: this server did not write it for that client", name, addrs)
		return
	}
	p.enqueue(job{name: name, addrs: addrs, dhcid: dhcid, remove: true})
}

// nameFor4 returns the name to write for a DHCPv4 client.
func (p *pluginState) nameFor4(req *dhcpv4.DHCPv4) (string, bool) {
	raw, wanted := hostname4(req)
	if !wanted {
		log.Debugf("%s asked for no DNS update", req.ClientHWAddr)
		return "", false
	}
	return p.hostFor(raw)
}

// hostFor turns a name a client sent into the name to write, or says in the
// debug log why nothing will be written.
//
// protect: is enforced here because both families and both directions funnel
// through it.
func (p *pluginState) hostFor(raw string) (string, bool) {
	name, err := hostFQDN(raw, p.zone)
	if err != nil {
		log.Debugf("not updating DNS for %q: %v", raw, err)
		return "", false
	}
	if p.protect[name] {
		log.Debugf("not updating DNS for %q: %s is protected", raw, name)
		return "", false
	}
	return name, true
}

// hostname4 returns the name a DHCPv4 client asked to be known by, and
// whether it wants an update at all.
//
// Option 81 wins over option 12: it is the option a client sends to say what
// it wants in DNS specifically, and it is the only one of the two that can
// say "nothing". A malformed option 81 falls back to option 12 rather than
// costing the client its record over a badly encoded name.
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

// fqdnName4 decodes the domain name of RFC 4702's option 81. The three octets
// in front of it are the flags and the two RCODE fields, which a server only
// ever echoes back.
func fqdnName4(raw []byte) (string, error) {
	body := raw[fqdn4HeaderLen:]
	if raw[0]&fqdn4FlagE == 0 {
		return string(body), nil
	}
	name, _, err := readName(body)
	return name, err
}

// address4 turns a DHCPv4 address field into an address worth writing.
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

// lease6 queues the records for the addresses a Reply hands out. Every IA_NA
// counts: a client may hold several addresses under one name, and they all
// belong in the same AAAA RRset.
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
	p.claim(name, addrs, identity6(req))
}

// release6 withdraws the records for the addresses a client is giving up. A
// Release names them in its own IA_NA options; the reply to it carries only a
// status code.
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
	p.withdraw(name, addrs, identity6(req))
}

// nameFor6 returns the name to write for a DHCPv6 client.
func (p *pluginState) nameFor6(req *dhcpv6.Message) (string, bool) {
	raw, wanted := hostname6(req)
	if !wanted {
		log.Debug("the client asked for no DNS update")
		return "", false
	}
	return p.hostFor(raw)
}

// hostname6 returns the name a DHCPv6 client asked for. RFC 4704's option 39
// carries the name in wire form only, and its N flag means what option 81's
// does.
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

// innerMessage unwraps a response, which is a relay chain when the request
// was relayed.
func innerMessage(msg dhcpv6.DHCPv6) (*dhcpv6.Message, error) {
	if msg == nil {
		return nil, errors.New("there is no response to read an address from")
	}
	return msg.GetInnerMessage()
}

// addresses6 returns the addresses of every IA_NA in msg.
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

// address6 turns a DHCPv6 address field into an address worth writing.
func address6(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
