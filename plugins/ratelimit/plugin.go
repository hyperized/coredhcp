// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ratelimit implements a plugin that drops DHCP requests arriving
// faster than a configured rate, so that one client cannot drain a pool or
// turn the server into a reflector by asking in a loop.
//
//	server4:
//	  plugins:
//	    - ratelimit: 20/s burst:50 per:mac max:65536 global:2000/s
//
// The first argument is the rate every client is held to, written as <n>/s or
// <n>/m with n a positive integer. The remaining arguments are optional, may
// appear in any order, and may appear once each:
//
//   - burst:<n>: the bucket size, how many requests a quiet client may send
//     back to back. Defaults to twice the per-second rate, never below 1.
//   - per:mac|source|both: what counts as a client (hardware address, source
//     address, or both). Defaults to mac.
//   - max:<n>: how many clients are tracked at once. Defaults to 65536.
//   - global:<n>/s or <n>/m: a second bucket shared by all traffic, with its
//     own burst (twice its rate). None by default.
//
// Security: every field a key is built from comes off the wire, so an
// attacker who varies it per packet gets a fresh bucket each time and never
// meets the per-client limit; global: is what still caps the total. The
// source key uses the peer address, not its port, since NAT hands out a
// fresh port per datagram.
//
// Placement: list ratelimit first, ahead of server_id and every allocator.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
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

var log = logger.GetLogger("plugins/ratelimit")

// Plugin wraps the ratelimit plugin information.
var Plugin = plugins.Plugin{
	Name:      "ratelimit",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

const (
	burstArg  = "burst:"
	perArg    = "per:"
	maxArg    = "max:"
	globalArg = "global:"

	perMAC    = "mac"
	perSource = "source"
	perBoth   = "both"

	periodSecond = "s"
	periodMinute = "m"

	defaultMaxKeys = 65536

	// Bounds so the arithmetic these numbers feed cannot overflow, and a typo
	// cannot ask for a table the machine has no memory for.
	maxRate    = 1_000_000
	maxBurst   = 10_000_000
	maxTracked = 1 << 20

	// The longest DUID RFC 8415 section 11.1 allows.
	maxIDLen = 130

	// 16-byte form netip uses for both families.
	addrLen = 16

	maxKeyLen = maxIDLen + addrLen

	summaryEvery = time.Minute
)

type mode uint8

const (
	modeMAC mode = iota
	modeSource
	modeBoth
)

// String names the mode the way a configuration file writes it.
func (m mode) String() string {
	switch m {
	case modeSource:
		return perSource
	case modeBoth:
		return perBoth
	default:
		return perMAC
	}
}

// With no peer info every mode falls back to the identifier, so a handler
// that can't assume RequestInfo never ends up sharing one bucket per client.
func (m mode) parts(havePeer bool) (id, peer bool) {
	if !havePeer {
		return true, false
	}
	return m != modeSource, m != modeMAC
}

type settings struct {
	interval time.Duration
	burst    int
	mode     mode
	maxKeys  int
	global   *limit
}

// Fixed at package init; read-only afterwards.
var optionParsers = []struct {
	prefix string
	apply  func(*settings, string) error
}{
	{burstArg, applyBurst},
	{perArg, applyPer},
	{maxArg, applyMax},
	{globalArg, applyGlobal},
}

func parseArgs(args []string) (*settings, error) {
	if len(args) == 0 {
		return nil, errors.New("need a rate as the first argument, for example 20/s or 600/m")
	}
	interval, perSecond, err := parseRate("rate", args[0])
	if err != nil {
		return nil, err
	}
	s := &settings{
		interval: interval,
		burst:    defaultBurst(perSecond),
		mode:     modeMAC,
		maxKeys:  defaultMaxKeys,
	}
	seen := make(map[string]struct{}, len(args))
	for _, arg := range args[1:] {
		if err := applyOption(s, seen, arg); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Refuses a second occurrence rather than quietly taking whichever came last.
func applyOption(s *settings, seen map[string]struct{}, arg string) error {
	for _, o := range optionParsers {
		raw, ok := strings.CutPrefix(arg, o.prefix)
		if !ok {
			continue
		}
		if _, dup := seen[o.prefix]; dup {
			return fmt.Errorf("%s given more than once", argName(o.prefix))
		}
		seen[o.prefix] = struct{}{}
		return o.apply(s, raw)
	}
	return fmt.Errorf("unknown argument %q, want one of %s<n>, %s%s|%s|%s, %s<n> or %s<rate>",
		arg, burstArg, perArg, perMAC, perSource, perBoth, maxArg, globalArg)
}

func argName(prefix string) string {
	return strings.TrimSuffix(prefix, ":")
}

func applyBurst(s *settings, raw string) error {
	n, err := parseCount(argName(burstArg), raw, maxBurst)
	if err != nil {
		return err
	}
	s.burst = n
	return nil
}

func applyPer(s *settings, raw string) error {
	switch raw {
	case perMAC:
		s.mode = modeMAC
	case perSource:
		s.mode = modeSource
	case perBoth:
		s.mode = modeBoth
	default:
		return fmt.Errorf("invalid %s%s, want %s, %s or %s", perArg, raw, perMAC, perSource, perBoth)
	}
	return nil
}

func applyMax(s *settings, raw string) error {
	n, err := parseCount(argName(maxArg), raw, maxTracked)
	if err != nil {
		return err
	}
	s.maxKeys = n
	return nil
}

// Its own burst comes from its own rate; reusing burst: here would size it off an unrelated number.
func applyGlobal(s *settings, raw string) error {
	interval, perSecond, err := parseRate(argName(globalArg), raw)
	if err != nil {
		return err
	}
	s.global = &limit{
		interval: interval,
		capacity: interval * time.Duration(defaultBurst(perSecond)),
	}
	return nil
}

// Truncated to whole nanoseconds, so a rate that doesn't divide its period
// evenly (e.g. 3/s) runs a few nanoseconds per second fast; nothing downstream cares.
func parseRate(name, raw string) (interval time.Duration, perSecond int, err error) {
	count, period, ok := strings.Cut(raw, "/")
	if !ok {
		return 0, 0, fmt.Errorf("invalid %s %q, want <n>/%s or <n>/%s", name, raw, periodSecond, periodMinute)
	}
	n, err := parseCount(name, count, maxRate)
	if err != nil {
		return 0, 0, err
	}
	switch period {
	case periodSecond:
		return time.Second / time.Duration(n), n, nil
	case periodMinute:
		return time.Minute / time.Duration(n), n / 60, nil
	default:
		return 0, 0, fmt.Errorf("invalid %s %q, want a period of %q or %q", name, raw, periodSecond, periodMinute)
	}
}

// Not an opinion about sensible rates: these numbers get multiplied together, and a config file is input like any other.
func parseCount(name, raw string, upper int) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q, want a whole number", name, raw)
	}
	if n < 1 || n > upper {
		return 0, fmt.Errorf("%s %d out of range, want 1 to %d", name, n, upper)
	}
	return n, nil
}

// A rate slower than one per second still gets a bucket of one; zero would mean it could never send anything.
func defaultBurst(perSecond int) int {
	if perSecond < 1 {
		return 1
	}
	return 2 * perSecond
}

// Fields from mu down are read only with mu held. One mutex for the whole
// instance is cheaper than any scheme for splitting the table would be.
type state struct {
	perKey limit
	mode   mode

	// A field, not time.Now, so a test can drive both refill and the summary
	// pace without sleeping.
	now func() time.Time

	// A field for the same reason as now, so a test can intercept it.
	warn func(format string, args ...any)

	mu          sync.Mutex
	table       *table
	global      *bucket
	globalLimit limit
	dropped     uint64
	distinct    uint64
	gen         uint64
	lastSummary time.Time
}

func newState(args ...string) (*state, error) {
	s, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	st := &state{
		perKey: limit{interval: s.interval, capacity: s.interval * time.Duration(s.burst)},
		mode:   s.mode,
		now:    time.Now,
		warn:   log.Warningf,
		table:  newTable(s.maxKeys),
		// Starts at 1 so a fresh bucket's zero-value gen differs, and its
		// first drop counts as a new distinct client.
		gen:         1,
		lastSummary: now,
	}
	if s.global != nil {
		st.globalLimit = *s.global
		st.global = &bucket{credit: s.global.capacity, last: now}
	}
	return st, nil
}

func setup4(args ...string) (handler.Handler4Ctx, error) {
	s, err := newState(args...)
	if err != nil {
		return nil, err
	}
	s.logLoaded("DHCPv4")
	return s.Handler4, nil
}

func setup6(args ...string) (handler.Handler6Ctx, error) {
	s, err := newState(args...)
	if err != nil {
		return nil, err
	}
	s.logLoaded("DHCPv6")
	return s.Handler6, nil
}

func (s *state) logLoaded(family string) {
	log.Infof("%s: one request per %s per %s, bursts of %d, tracking at most %d clients",
		family, s.perKey.interval, s.mode, s.perKey.tokens(), s.table.maxKeys)
	if s.global != nil {
		log.Infof("%s: shared limit of one request per %s, bursts of %d",
			family, s.globalLimit.interval, s.globalLimit.tokens())
	}
}

// Handler4 handles DHCPv4 packets for the ratelimit plugin.
func (s *state) Handler4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	var buf [maxKeyLen]byte
	if s.allow(s.key(ctx, &buf, req.ClientHWAddr)) {
		return resp, false
	}
	return nil, true
}

// Handler6 handles DHCPv6 packets for the ratelimit plugin.
func (s *state) Handler6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	var buf [maxKeyLen]byte
	if s.allow(s.key(ctx, &buf, clientID6(req))) {
		return resp, false
	}
	return nil, true
}

// A nil result is keyed on source address instead, or shares one bucket
// under per:mac.
func clientID6(req dhcpv6.DHCPv6) []byte {
	if mac, err := dhcpv6.ExtractMAC(req); err == nil {
		return mac
	}
	msg, err := req.GetInnerMessage()
	if err != nil {
		return nil
	}
	duid := msg.Options.ClientID()
	if duid == nil {
		return nil
	}
	return duid.ToBytes()
}

// buf belongs to the caller, so this allocates nothing; the result must not
// outlive the call.
func (s *state) key(ctx context.Context, buf *[maxKeyLen]byte, id []byte) []byte {
	info, ok := handler.RequestInfoFrom(ctx)
	useID, usePeer := s.mode.parts(ok)
	n := 0
	if useID {
		n += copy(buf[n:], clampID(id))
	}
	if usePeer {
		addr := info.Peer.Addr().As16()
		n += copy(buf[n:], addr[:])
	}
	return buf[:n]
}

// RFC 8415 section 11.1 bounds a DUID; nothing on the wire is trusted to
// honor that, so this keeps a key from overrunning into the peer address under per:both.
func clampID(id []byte) []byte {
	if len(id) > maxIDLen {
		return id[:maxIDLen]
	}
	return id
}

// Passed out from under the mutex so formatting and logging happen outside it.
type summary struct {
	emit     bool
	dropped  uint64
	distinct uint64
	over     time.Duration
}

func (s *state) allow(key []byte) bool {
	s.mu.Lock()
	allowed, sum := s.consume(key)
	s.mu.Unlock()
	if sum.emit {
		s.warn("dropped %d requests over the last %s, %d distinct keys",
			sum.dropped, sum.over.Round(time.Second), sum.distinct)
	}
	return allowed
}

// Runs with mu held.
func (s *state) consume(key []byte) (bool, summary) {
	now := s.now()
	b := s.table.fetch(key, now, s.perKey.capacity)
	if b.allow(now, s.perKey) && s.allowGlobal(now) {
		return true, summary{}
	}
	return false, s.recordDrop(b, now)
}

// Reached only once the per-client bucket has paid, so a client already
// over its own limit doesn't also spend the shared budget.
func (s *state) allowGlobal(now time.Time) bool {
	if s.global == nil {
		return true
	}
	return s.global.allow(now, s.globalLimit)
}

func (s *state) recordDrop(b *bucket, now time.Time) summary {
	s.dropped++
	if b.gen != s.gen {
		b.gen = s.gen
		s.distinct++
	}
	if now.Sub(s.lastSummary) < summaryEvery {
		return summary{}
	}
	sum := summary{
		emit:     true,
		dropped:  s.dropped,
		distinct: s.distinct,
		over:     now.Sub(s.lastSummary),
	}
	s.dropped, s.distinct = 0, 0
	s.gen++
	s.lastSummary = now
	return sum
}
