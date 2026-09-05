// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ratelimit implements a plugin that drops DHCP requests arriving
// faster than a configured rate, so that one client cannot drain a pool or
// turn the server into a reflector by asking in a loop.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - ratelimit: 20/s burst:50 per:mac max:65536 global:2000/s
//
// The first argument is the rate every client is held to, written as <n>/s or
// <n>/m with n a positive integer. The remaining arguments are optional, may
// appear in any order, and may appear once each. An argument that is none of
// them fails setup by name.
//
//   - burst:<n> is the bucket size: how many requests a client that has been
//     quiet may send back to back before the rate starts to bite. It defaults
//     to twice the per-second rate, and never to less than 1.
//   - per:mac|source|both picks what counts as a client. mac keys on the
//     client's hardware address, source on the address the datagram came
//     from, both on the two together. The default is mac.
//   - max:<n> bounds how many clients are tracked at once, and defaults to
//     65536.
//   - global:<n>/s or <n>/m adds a second bucket that all traffic shares.
//     There is none by default. Its own burst is twice its per-second rate;
//     burst: does not apply to it.
//
// # How it works
//
// Every tracked client owns a token bucket holding burst tokens, refilled at
// the configured rate and charged one token per request. The refill happens
// when the bucket is looked at, so there is no timer and no goroutine, and a
// quiet client costs nothing between requests. A request that finds its own
// bucket empty is dropped, and so is one that finds the global bucket empty,
// in that order. Dropping ends the handler chain and sends nothing, so the
// client retries a moment later, which is what a DHCP client does with a lost
// packet anyway.
//
// Drops are not logged one at a time: a line per dropped packet is a way to
// fill the disk of the machine you are defending. A summary goes to the log
// at warning level at most once a minute instead, naming how many requests
// were dropped and how many distinct clients they came from.
//
// # Bounds, and what an attacker can do inside them
//
// The client table is an LRU capped at max entries, where a new client beyond
// the cap evicts the one seen longest ago. Every field a key is built from
// comes off the wire, so an attacker who varies the hardware address or the
// source address per packet gets a fresh entry each time, pushes real clients
// out of the table, and never meets the per-client limit because their bucket
// is always new. That is a property of keying on identifiers nobody
// authenticated, and a larger table does not fix it. global: is the answer
// for that case: there is one such bucket, an attacker cannot obtain a
// second, and it caps what the server will do in total.
//
// The source key uses the peer address and not its port. A client behind NAT
// picks a fresh source port per datagram, so keying on the port would hand
// out a fresh bucket per packet.
//
// # Identifying a client
//
// On DHCPv4 the key is chaddr, the hardware address the client wrote into the
// request itself. On DHCPv6 it is whatever dhcpv6.ExtractMAC finds, meaning
// the relay's link-layer option, an EUI-64 peer address, or a DUID-LL or
// DUID-LLT; when that finds nothing, the raw client DUID serves instead,
// truncated to the 130 bytes RFC 8415 section 11.1 allows a DUID to be. A
// message carrying neither is keyed on its source address under per:source
// and per:both, and shares one bucket with every other such message under
// per:mac.
//
// A ratelimit line under server4 and one under server6 are separate
// instances with separate tables, so a client speaking both families is held
// to the rate once per family.
//
// # Placement
//
// List ratelimit first, ahead of server_id and every allocator, so that a
// client over its limit costs the server a map lookup and nothing more.
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
//
// Both setup functions are the context-aware form, because per:source and
// per:both need the peer address, and that is only in the context.
var Plugin = plugins.Plugin{
	Name:      "ratelimit",
	Setup4Ctx: setup4,
	Setup6Ctx: setup6,
}

const (
	// Prefixes of the optional arguments.
	burstArg  = "burst:"
	perArg    = "per:"
	maxArg    = "max:"
	globalArg = "global:"

	// Values per: accepts.
	perMAC    = "mac"
	perSource = "source"
	perBoth   = "both"

	// Periods a rate may be written in.
	periodSecond = "s"
	periodMinute = "m"

	// defaultMaxKeys is how many clients are tracked when max: is absent.
	defaultMaxKeys = 65536

	// Upper bounds on what a configuration file may ask for. They are here
	// so that the arithmetic these numbers feed cannot be made to overflow,
	// and so a typo cannot ask for a table the machine has no memory for.
	maxRate    = 1_000_000
	maxBurst   = 10_000_000
	maxTracked = 1 << 20

	// maxIDLen is the longest client identifier a key carries, which is the
	// longest DUID RFC 8415 section 11.1 allows.
	maxIDLen = 130

	// addrLen is an address in the 16-byte form netip uses for both families.
	addrLen = 16

	// maxKeyLen sizes the stack buffer a key is built in.
	maxKeyLen = maxIDLen + addrLen

	// summaryEvery is how often the drop summary may be logged.
	summaryEvery = time.Minute
)

// mode says which part of a request identifies the client whose bucket pays.
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

// parts reports which halves of the key this mode uses.
//
// havePeer is false when the context carried no handler.RequestInfo, which
// this server always provides but a handler must not assume. Without it there
// is no source address to key on, so every mode falls back to the client
// identifier rather than letting every client share one bucket.
func (m mode) parts(havePeer bool) (id, peer bool) {
	if !havePeer {
		return true, false
	}
	return m != modeSource, m != modeMAC
}

// settings is one plugin line, parsed. burst is kept apart from the interval
// until the end because burst: may follow the rate on the line.
type settings struct {
	interval time.Duration
	burst    int
	mode     mode
	maxKeys  int
	global   *limit
}

// optionParsers maps each optional argument to its parser. It is a fixed
// table, read only after initialization.
var optionParsers = []struct {
	prefix string
	apply  func(*settings, string) error
}{
	{burstArg, applyBurst},
	{perArg, applyPer},
	{maxArg, applyMax},
	{globalArg, applyGlobal},
}

// parseArgs turns a configuration line into settings, applying the defaults
// first so that an argument only ever overrides one of them.
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

// applyOption dispatches one optional argument to its parser, and refuses a
// second occurrence of the same one instead of quietly taking whichever came
// last.
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

// argName is an argument prefix without its colon, for error messages.
func argName(prefix string) string {
	return strings.TrimSuffix(prefix, ":")
}

// applyBurst sets the per-client bucket size.
func applyBurst(s *settings, raw string) error {
	n, err := parseCount(argName(burstArg), raw, maxBurst)
	if err != nil {
		return err
	}
	s.burst = n
	return nil
}

// applyPer picks what a client is keyed on.
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

// applyMax bounds the client table.
func applyMax(s *settings, raw string) error {
	n, err := parseCount(argName(maxArg), raw, maxTracked)
	if err != nil {
		return err
	}
	s.maxKeys = n
	return nil
}

// applyGlobal adds the bucket shared by all traffic. Its burst comes from its
// own rate, since burst: is documented as the per-client bucket size and
// reusing it here would size the shared bucket off an unrelated number.
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

// parseRate reads the <n>/s or <n>/m form, returning the time one token takes
// to accrue along with the whole requests per second the rate works out to,
// which is what the default burst is derived from.
//
// The interval is truncated to whole nanoseconds, so a rate that does not
// divide its period evenly, such as 3/s, comes out a few nanoseconds per
// second fast. Nothing downstream cares at that scale.
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

// parseCount reads a positive integer no larger than upper. The bound is not
// an opinion about sensible rates; it is there because these numbers get
// multiplied together and a configuration file is input like any other.
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

// defaultBurst lets a client that has been quiet spend two seconds of its
// rate at once. A rate slower than one per second still gets a bucket of one,
// or it could never send anything at all.
func defaultBurst(perSecond int) int {
	if perSecond < 1 {
		return 1
	}
	return 2 * perSecond
}

// state is one loaded instance of the plugin: the parsed limits, the table of
// per-client buckets, and the drop accounting behind the summary log.
//
// Everything from mu down is written on the request path and read only with
// mu held, so an instance is safe for the one goroutine per packet the server
// runs. One mutex for the whole instance is deliberate: what it guards is a
// map lookup and a handful of integer operations, which is cheaper than any
// scheme for splitting the table would be.
type state struct {
	perKey limit
	mode   mode

	// now reads the clock. Buckets refill from it and the summary is paced
	// by it, so a test drives both by replacing it instead of sleeping.
	now func() time.Time

	// warn emits the drop summary, and is a field for the same reason now is.
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

// newState parses the arguments and builds the instance behind them.
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
		// Buckets start at generation 0, so the first drop on any of them
		// counts towards the distinct clients in the first window.
		gen:         1,
		lastSummary: now,
	}
	if s.global != nil {
		st.globalLimit = *s.global
		st.global = &bucket{credit: s.global.capacity, last: now}
	}
	return st, nil
}

// setup4 builds the DHCPv4 handler for one configured ratelimit line.
func setup4(args ...string) (handler.Handler4Ctx, error) {
	s, err := newState(args...)
	if err != nil {
		return nil, err
	}
	s.logLoaded("DHCPv4")
	return s.Handler4, nil
}

// setup6 is setup4 for DHCPv6.
func setup6(args ...string) (handler.Handler6Ctx, error) {
	s, err := newState(args...)
	if err != nil {
		return nil, err
	}
	s.logLoaded("DHCPv6")
	return s.Handler6, nil
}

// logLoaded says at startup what this instance will do, since a limit nobody
// can see is a limit somebody will spend an afternoon on.
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

// clientID6 finds something to identify a DHCPv6 client by. ExtractMAC covers
// the relay's link-layer option, an EUI-64 peer address, and the DUID forms
// that embed a hardware address; for every other DUID the bytes of the DUID
// itself serve just as well here. A message with neither returns nil and is
// keyed on its source address, or under per:mac shares one bucket with every
// other such message.
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

// key writes the client's key into buf and returns the filled part of it. buf
// belongs to the caller, so building a key allocates nothing, and the result
// must not outlive the call.
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

// clampID cuts a client identifier down to the longest DUID RFC 8415 section
// 11.1 permits. Nothing on the wire is trusted to stay within that, and a
// fixed bound is what keeps a key from running into the peer address behind
// it under per:both.
func clampID(id []byte) []byte {
	if len(id) > maxIDLen {
		return id[:maxIDLen]
	}
	return id
}

// summary is what one drop decided about the periodic log line: nothing, or
// the counts to print now. It comes back out from under the mutex so that
// formatting and writing the line happen outside it.
type summary struct {
	emit     bool
	dropped  uint64
	distinct uint64
	over     time.Duration
}

// allow charges one request to key's bucket, and to the shared bucket when
// there is one. It reports false when the request has to be dropped.
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

// consume does the accounting. It runs with mu held.
func (s *state) consume(key []byte) (bool, summary) {
	now := s.now()
	b := s.table.fetch(key, now, s.perKey.capacity)
	if b.allow(now, s.perKey) && s.allowGlobal(now) {
		return true, summary{}
	}
	return false, s.recordDrop(b, now)
}

// allowGlobal charges the bucket all traffic shares, and passes everything
// when global: was not configured. It is reached only once the per-client
// bucket has paid, so a client already over its own limit does not also spend
// the server's shared budget.
func (s *state) allowGlobal(now time.Time) bool {
	if s.global == nil {
		return true
	}
	return s.global.allow(now, s.globalLimit)
}

// recordDrop counts one dropped request and reports whether that drop is the
// one that gets to log the summary for the window just ended.
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
