// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package relay decides which relayed DHCP requests this server answers, and
// checks that a client releasing a lease speaks from the address it is
// releasing. Both checks work from what the network layer says about a
// datagram, not from what the packet claims about itself.
//
//	server4/server6:
//	  plugins:
//	    - relay: allow 10.0.1.1 10.0.2.0/24 fe80::/10 strict-giaddr release-check:on
//
// The first argument is the keyword allow, followed by one or more addresses
// or CIDR prefixes. Both families may be listed on one line: the DHCPv4
// handler consults the IPv4 entries and the DHCPv6 handler the IPv6 ones, so
// a single configuration serves a dual-stack server. An empty allow list, a
// malformed entry or an option given twice fails setup, and the error names
// the argument that caused it.
//
// The remaining arguments are options, in any order and at most once each:
//
//   - strict-giaddr: on DHCPv4, additionally require the datagram's source
//     address to equal giaddr. Off by default, because RFC 1542 section 4.1
//     lets a multi-homed relay forward from an interface other than the one
//     whose address it put in giaddr, and that mismatch is legitimate. Turn
//     it on when the relays are known to be single-homed.
//   - release-check:on|off: whether to drop a DHCPRELEASE whose ciaddr does
//     not match the datagram's source. On by default.
//
// # What this fixes
//
// On DHCPv4 the server sends its reply to giaddr, at the source port of the
// request, whenever giaddr is set. Both are picked by whoever sent the
// packet, so with no check any host on the segment can make the server send
// an OFFER to any routable address, and the OFFER is larger than the
// DISCOVER that triggered it. The allow list settles that by naming the
// relays that are actually deployed. Everything else is dropped before a
// lease is touched.
//
// The other half is DHCPRELEASE. A release carries the client's chaddr and
// ciaddr and nothing that ties either to the sender, so a host that knows a
// neighbour's address and MAC can free the neighbour's lease. RFC 2131
// section 4.4.6 has the client unicast the release from the address it is
// giving up, so comparing ciaddr against the datagram's source costs nothing
// and rules out the forgery from off-link and from any other address
// on-link. DHCPDECLINE gets no such check, because it carries no ciaddr to
// compare against.
//
// # DHCPv6
//
// A DHCPv6 relay puts no address in the client's packet the way giaddr does.
// It wraps the message in a Relay-forward and the server replies to the
// datagram's source, so the allow list is matched against that source.
// Relays usually forward from a link-local address, which is why
// fe80::/10 is a sensible entry: it admits any on-link relay while still
// refusing anything routed in from elsewhere.
//
// Two shape checks come with it. A relay chain nested deeper than eight
// layers is dropped, and so is an outermost Relay-forward that carries no
// link address and a hop count above the RFC 8415 HOP_COUNT_LIMIT of 32
// (section 7.6, applied by relays themselves in section 19.1.1). Neither
// occurs in a working deployment, and both are cheap ways to hand the server
// a packet that costs more to process than it did to send.
//
// # Failing closed
//
// The checks need handler.RequestInfo, which the server attaches to the
// request context. A relayed request that arrives without it is dropped in
// both families: the handler is then running outside the server's dispatch
// path, where none of what it is asked to guarantee holds, and the safe
// answer to a request it cannot attribute is no answer. The release
// check is the exception. It is an extra on top of an otherwise ordinary
// on-link request, so a release with no request information passes instead of
// being dropped.
//
// # What this is not
//
// This filters on where packets come from. It is not authentication. A host
// sharing a segment with a trusted relay can still source packets from the
// relay's address if nothing on the switch stops it, and the DHCPv6 check
// trusts an unauthenticated source address in the same way. What it does buy
// is that neither attack above is free any more: both now need a foothold in
// a specific place. Port security, DHCP snooping and IP source guard are what
// hold that ground.
//
// # Placement
//
// relay belongs first in the chain, or straight after a rate limiter, and in
// any case before server_id and before any plugin that allocates or frees a
// lease. The point of it is that a rejected packet never reaches lease state.
//
// # Logging
//
// Drops are logged at Info with the reason and the addresses involved, at
// most one line per second per reason, so a flood of rejected packets does
// not become a flood of log lines. The reasons are a fixed set of constants,
// so the limiter's bookkeeping is bounded by that set and cannot grow with
// traffic.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/relay")

// Plugin wraps the relay plugin information.
//
// Both families use the context-aware setup functions, because the source
// address of the datagram is the one thing this plugin is built around and it
// exists nowhere in the DHCP payload.
var Plugin = plugins.Plugin{
	Name:      "relay",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

const (
	// keywordAllow introduces the allow list and must be the first argument.
	keywordAllow = "allow"

	// optStrictGiaddr turns on the DHCPv4 source-equals-giaddr check.
	optStrictGiaddr = "strict-giaddr"

	// optReleaseCheck prefixes the release-check:on|off option.
	optReleaseCheck = "release-check:"

	// hopCountLimit is HOP_COUNT_LIMIT from RFC 8415 section 7.6.
	hopCountLimit = 32

	// maxRelayDepth is how many nested Relay-forward layers are accepted.
	// RFC 8415 sets no limit of its own beyond the hop count, and a real
	// chain is one or two layers deep.
	maxRelayDepth = 8

	// logInterval is how often one drop reason may produce a log line.
	logInterval = time.Second
)

// Setup errors that callers and tests can match with errors.Is. Errors that
// have to quote the offending argument are built with fmt.Errorf instead.
var (
	errNoAllowKeyword = errors.New("first argument must be `allow`, followed by addresses or prefixes")
	errNoAllowEntries = errors.New("need at least one address or prefix after `allow`")
	errRepeatedOption = errors.New("option given more than once")
	errMappedEntry    = errors.New("IPv4-mapped IPv6 entry never matches, write it as a plain IPv4 address")
	errZonedEntry     = errors.New("zoned address never matches, the interface is matched separately")
)

// reason names one cause for dropping a request. Every value is a constant,
// which is what keeps the drop limiter's map bounded by the set below rather
// than by the traffic it sees.
type reason string

const (
	reasonNoRequestInfo    reason = "no request information"
	reasonGiaddrNotAllowed reason = "giaddr not in the allow list"
	reasonGiaddrMismatch   reason = "source address does not match giaddr"
	reasonReleaseMismatch  reason = "release source does not match ciaddr"
	reasonPeerNotAllowed   reason = "relay source not in the allow list"
	reasonHopCount         reason = "hop count above the limit"
	reasonRelayDepth       reason = "relay chain too deep"
)

// dropLimiter holds back repeated drop log lines, one per reason per
// logInterval.
//
// It is the only mutable state in the plugin and the only thing the two
// handlers share across goroutines, which is why it carries the mutex:
// everything else is written once during setup and only read afterwards.
type dropLimiter struct {
	// now reads the clock. It is a field so tests can step over the interval
	// instead of sleeping through it.
	now func() time.Time

	mu   sync.Mutex
	last map[reason]time.Time
}

// newDropLimiter returns a limiter that permits one line per reason per
// logInterval, reading the clock through now.
func newDropLimiter(now func() time.Time) *dropLimiter {
	return &dropLimiter{now: now, last: make(map[reason]time.Time)}
}

// allow reports whether a line for r may be logged, and if so records when it
// was. A reason not seen before is always allowed.
func (l *dropLimiter) allow(r reason) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if prev, ok := l.last[r]; ok && t.Sub(prev) < logInterval {
		return false
	}
	l.last[r] = t
	return true
}

// pluginState is one configured instance of the plugin. setup4 and setup6
// each build their own, so a server that lists relay in both sections gets
// two independent states and two independent log limiters.
//
// Everything but the limiter is written during setup and read-only from then
// on, so the handlers are safe to call concurrently.
type pluginState struct {
	allow4       []netip.Prefix
	allow6       []netip.Prefix
	strictGiaddr bool
	releaseCheck bool
	limiter      *dropLimiter
}

func setup4(args ...string) (handler.Handler4Ctx, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6Ctx, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

// setupState parses the arguments shared by setup4 and setup6.
func setupState(args ...string) (*pluginState, error) {
	if len(args) == 0 || args[0] != keywordAllow {
		return nil, errNoAllowKeyword
	}
	p := &pluginState{
		releaseCheck: true,
		limiter:      newDropLimiter(time.Now),
	}
	seen := make(map[string]bool, 2)
	for _, arg := range args[1:] {
		if err := p.applyArg(arg, seen); err != nil {
			return nil, err
		}
	}
	if len(p.allow4)+len(p.allow6) == 0 {
		return nil, errNoAllowEntries
	}
	log.Infof("allowing %d IPv4 and %d IPv6 relay source(s), strict-giaddr %t, release-check %t",
		len(p.allow4), len(p.allow6), p.strictGiaddr, p.releaseCheck)
	return p, nil
}

// applyArg folds one argument after the allow keyword into p. Anything that
// is not a recognised option is taken as an allow list entry, so the options
// may appear before, between or after the addresses.
func (p *pluginState) applyArg(arg string, seen map[string]bool) error {
	switch {
	case arg == optStrictGiaddr:
		if err := markSeen(seen, optStrictGiaddr); err != nil {
			return err
		}
		p.strictGiaddr = true
		return nil
	case strings.HasPrefix(arg, optReleaseCheck):
		if err := markSeen(seen, optReleaseCheck); err != nil {
			return err
		}
		return p.setReleaseCheck(strings.TrimPrefix(arg, optReleaseCheck))
	default:
		return p.addAllowEntry(arg)
	}
}

// markSeen records that an option has been given, rejecting a second one.
// Two contradictory release-check arguments would otherwise be resolved by
// argument order, which is not something a configuration file should decide
// silently.
func markSeen(seen map[string]bool, key string) error {
	if seen[key] {
		return fmt.Errorf("%w: %s", errRepeatedOption, strings.TrimSuffix(key, ":"))
	}
	seen[key] = true
	return nil
}

// setReleaseCheck applies the value of the release-check option.
func (p *pluginState) setReleaseCheck(value string) error {
	switch value {
	case "on":
		p.releaseCheck = true
	case "off":
		p.releaseCheck = false
	default:
		return fmt.Errorf("invalid release-check value %q, expected `on` or `off`", value)
	}
	return nil
}

// addAllowEntry parses one allow list entry and files it under its family.
func (p *pluginState) addAllowEntry(arg string) error {
	prefix, err := parseAllowEntry(arg)
	if err != nil {
		return err
	}
	if prefix.Addr().Is4() {
		p.allow4 = append(p.allow4, prefix)
		return nil
	}
	p.allow6 = append(p.allow6, prefix)
	return nil
}

// parseAllowEntry turns one argument into a prefix. A bare address becomes a
// host prefix, so both forms compare the same way afterwards.
//
// Two spellings are refused rather than accepted and quietly ignored: an
// IPv4-mapped IPv6 entry, which netip never matches against an unmapped
// address, and a zoned address, which never matches because the server strips
// the zone before a plugin sees the peer. Both would look configured and
// admit nothing.
func parseAllowEntry(arg string) (netip.Prefix, error) {
	if strings.Contains(arg, "/") {
		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", arg, err)
		}
		if prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("prefix %q: %w", arg, errMappedEntry)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(arg)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q: %w", arg, err)
	}
	if addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("address %q: %w", arg, errMappedEntry)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("address %q: %w", arg, errZonedEntry)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// allowed reports whether addr falls inside any of the configured prefixes.
// The list is walked linearly: it is operator-written and short, and a linear
// walk over a handful of prefixes beats building anything cleverer per
// packet.
func allowed(prefixes []netip.Prefix, addr netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// logDrop reports a dropped request at Info, at most once per interval per
// reason.
func (p *pluginState) logDrop(r reason, format string, args ...any) {
	if !p.limiter.allow(r) {
		return
	}
	log.Infof("dropping request (%s): %s", r, fmt.Sprintf(format, args...))
}

// packetAddr converts a DHCPv4 header address field to a netip.Addr and
// reports whether it names a host. An unset field reaches us as nil, as four
// zero bytes, or as 0.0.0.0 in 16-byte form, and all three mean the same
// thing.
func packetAddr(ip net.IP) (netip.Addr, bool) {
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

// peerAddr returns the source address of the datagram, unmapped. The server
// has already stripped the IPv6 zone; unmapping as well means an IPv4 peer
// read off a dual-stack socket compares equal to the same address written in
// dotted-quad form in the configuration.
func peerAddr(info handler.RequestInfo) netip.Addr {
	return info.Peer.Addr().Unmap()
}

// Handler4 handles DHCPv4 packets for the relay plugin.
func (p *pluginState) Handler4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	giaddr, relayed := packetAddr(req.GatewayIPAddr)
	if !relayed {
		return p.checkOnLink4(ctx, req, resp)
	}
	return p.checkRelayed4(ctx, giaddr, resp)
}

// checkRelayed4 passes a request whose giaddr names a configured relay.
//
// A giaddr that is not an IPv4 address at all cannot appear on the wire,
// where the field is four bytes wide, but it can be built by hand. It fails
// the allow list like any other unknown address, so it is dropped without
// needing a case of its own.
func (p *pluginState) checkRelayed4(ctx context.Context, giaddr netip.Addr, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if !allowed(p.allow4, giaddr) {
		p.logDrop(reasonGiaddrNotAllowed, "giaddr %s", giaddr)
		return nil, true
	}
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		p.logDrop(reasonNoRequestInfo, "relayed request with giaddr %s", giaddr)
		return nil, true
	}
	if peer := peerAddr(info); p.strictGiaddr && peer != giaddr {
		p.logDrop(reasonGiaddrMismatch, "giaddr %s, source %s", giaddr, peer)
		return nil, true
	}
	return resp, false
}

// checkOnLink4 passes a request from a client on the server's own link,
// except for the release check.
//
// A DHCPRELEASE with no ciaddr at all is dropped along with a mismatched one:
// the field is mandatory in a release (RFC 2131 section 4.4.6) and its
// absence leaves nothing to check the sender against.
func (p *pluginState) checkOnLink4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if !p.releaseCheck || req.MessageType() != dhcpv4.MessageTypeRelease {
		return resp, false
	}
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		// The release check is an extra, not a gate: without the server's
		// view of the datagram there is nothing to compare, and the request
		// is otherwise an ordinary on-link one.
		return resp, false
	}
	ciaddr, _ := packetAddr(req.ClientIPAddr)
	peer := peerAddr(info)
	if ciaddr != peer {
		p.logDrop(reasonReleaseMismatch, "ciaddr %s, source %s", req.ClientIPAddr, peer)
		return nil, true
	}
	return resp, false
}

// Handler6 handles DHCPv6 packets for the relay plugin.
//
// Only a *dhcpv6.RelayMessage answers true to IsRelay in this library, so the
// type assertion is both the relay test and the way to reach the header
// fields the shape checks read.
func (p *pluginState) Handler6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	relay, isRelay := req.(*dhcpv6.RelayMessage)
	if !isRelay {
		return resp, false
	}
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		p.logDrop(reasonNoRequestInfo, "relayed DHCPv6 request")
		return nil, true
	}
	peer := peerAddr(info)
	if !allowed(p.allow6, peer) {
		p.logDrop(reasonPeerNotAllowed, "source %s", peer)
		return nil, true
	}
	return p.checkRelayShape(relay, resp)
}

// checkRelayShape rejects a relayed message whose header says it has been
// around too long or has been wrapped too many times.
func (p *pluginState) checkRelayShape(relay *dhcpv6.RelayMessage, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if unspecifiedLink(relay.LinkAddr) && relay.HopCount > hopCountLimit {
		p.logDrop(reasonHopCount, "no link address, hop count %d above %d", relay.HopCount, hopCountLimit)
		return nil, true
	}
	if relayDepth(relay) > maxRelayDepth {
		p.logDrop(reasonRelayDepth, "more than %d nested relays", maxRelayDepth)
		return nil, true
	}
	return resp, false
}

// unspecifiedLink reports whether a Relay-forward carries no link address,
// which RFC 8415 section 19.1.1 writes as the unspecified address. An absent
// field decodes to a nil slice and means the same thing.
func unspecifiedLink(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return !ok || addr.IsUnspecified()
}

// relayDepth counts the Relay-forward layers wrapping a client's message.
//
// GetInnerMessage recurses to the innermost message without saying how far it
// went, so the layers are counted here instead. The walk stops one layer past
// maxRelayDepth: a chain that is already too deep is going to be dropped, and
// stopping keeps the count bounded no matter how deeply the sender nested the
// packet.
func relayDepth(relay *dhcpv6.RelayMessage) int {
	var msg dhcpv6.DHCPv6 = relay
	depth := 0
	for depth <= maxRelayDepth {
		inner, ok := msg.(*dhcpv6.RelayMessage)
		if !ok {
			break
		}
		depth++
		msg = inner.Options.RelayMessage()
		if msg == nil {
			break
		}
	}
	return depth
}
