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
// a single configuration serves a dual-stack server.
//
// The remaining arguments are options, in any order and at most once each:
//
//   - strict-giaddr: on DHCPv4, additionally require the datagram's source
//     address to equal giaddr. Off by default: RFC 1542 section 4.1 lets a
//     multi-homed relay forward from an interface other than the one whose
//     address it put in giaddr.
//   - release-check:on|off: drop a DHCPRELEASE whose ciaddr does not match
//     the datagram's source (RFC 2131 section 4.4.6). On by default.
//
// Security: without the allow list, any host on the segment can make the
// server send a DHCPv4 reply to an arbitrary routable address via giaddr, or
// free another client's lease with a forged DHCPRELEASE. This is a source
// filter, not authentication: a host sharing a segment with a trusted relay
// can still spoof its address unless the switch enforces port security, DHCP
// snooping or IP source guard.
//
// Placement: first in the chain, or right after a rate limiter, and always
// before server_id and any plugin that allocates or frees a lease.
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
var Plugin = plugins.Plugin{
	Name:      "relay",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

const (
	keywordAllow = "allow"

	optStrictGiaddr = "strict-giaddr"

	optReleaseCheck = "release-check:"

	// hopCountLimit is HOP_COUNT_LIMIT from RFC 8415 section 7.6.
	hopCountLimit = 32

	// maxRelayDepth is not RFC-mandated; RFC 8415 caps only the hop count,
	// and a real relay chain is one or two layers deep.
	maxRelayDepth = 8

	logInterval = time.Second
)

// Sentinel errors so callers and tests can match with errors.Is; errors that
// quote the offending argument use fmt.Errorf instead.
var (
	errNoAllowKeyword = errors.New("first argument must be `allow`, followed by addresses or prefixes")
	errNoAllowEntries = errors.New("need at least one address or prefix after `allow`")
	errRepeatedOption = errors.New("option given more than once")
	errMappedEntry    = errors.New("IPv4-mapped IPv6 entry never matches, write it as a plain IPv4 address")
	errZonedEntry     = errors.New("zoned address never matches, the interface is matched separately")
)

// A closed set of constants keeps the drop limiter's map bounded by this
// list, not by traffic.
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

// The only mutable state in the plugin and the only thing the two handlers
// share across goroutines, hence the mutex.
type dropLimiter struct {
	// Field, not time.Now, so tests can step over the interval instead of sleeping.
	now func() time.Time

	mu   sync.Mutex
	last map[reason]time.Time
}

func newDropLimiter(now func() time.Time) *dropLimiter {
	return &dropLimiter{now: now, last: make(map[reason]time.Time)}
}

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

// Read-only once setup returns, except for the limiter, so handlers may run concurrently.
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

// Unmatched options fall through as allow entries, so options may appear in any order.
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

// Rejects a repeat so contradictory options are not resolved by argument order.
func markSeen(seen map[string]bool, key string) error {
	if seen[key] {
		return fmt.Errorf("%w: %s", errRepeatedOption, strings.TrimSuffix(key, ":"))
	}
	seen[key] = true
	return nil
}

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

// A bare address becomes a host prefix so both forms compare the same way.
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

// Linear scan: the list is operator-written and short, so nothing fancier pays for itself.
func allowed(prefixes []netip.Prefix, addr netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

func (p *pluginState) logDrop(r reason, format string, args ...any) {
	if !p.limiter.allow(r) {
		return
	}
	log.Infof("dropping request (%s): %s", r, fmt.Sprintf(format, args...))
}

// An unset field arrives as nil, four zero bytes, or 0.0.0.0 in 16-byte form; all three mean unset.
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

// Unmapped so an IPv4 peer read off a dual-stack socket compares equal to
// the dotted-quad form written in the config.
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

// A giaddr that isn't a valid IPv4 address can't appear on the wire but can
// be built by hand; it simply fails the allow list, no separate case needed.
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

// RFC 2131 section 4.4.6: ciaddr is mandatory in a release, so a missing one is dropped like a mismatched one.
func (p *pluginState) checkOnLink4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if !p.releaseCheck || req.MessageType() != dhcpv4.MessageTypeRelease {
		return resp, false
	}
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		// An extra check, not a gate: with no request info there's nothing to
		// compare against, so let the otherwise-ordinary release through.
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

// RFC 8415 section 19.1.1: no link address is written as the unspecified
// address; an absent field decodes to nil, which means the same thing.
func unspecifiedLink(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return !ok || addr.IsUnspecified()
}

// Counts manually since GetInnerMessage doesn't report depth, and stops one
// layer past maxRelayDepth so a deeply nested packet can't make this unbounded.
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
