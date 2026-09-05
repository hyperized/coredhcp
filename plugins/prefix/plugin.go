// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package prefix implements a plugin offering prefixes to clients requesting
// them with IA_PREFIX requests.
//
// The plugin takes the pool and the allocation size, and optionally a lease
// duration and named arguments in any order:
//
//	server6:
//	  plugins:
//	    - prefix: 2001:db8::/48 64 1h sweep:30m max-prefixes:4
//
// The pool is the base prefix that assigned prefixes are carved from, and has
// to be an IPv6 prefix: delegation only exists for DHCPv6. The allocation size
// is the largest prefix handed to a client: one asking for something bigger
// gets a prefix of this size. The lease duration defaults to 1h.
//
//	sweep:<duration>       how often lapsed delegations are reclaimed in the
//	                       background. Defaults to half the lease duration,
//	                       floored at 30s.
//	max-prefixes:<count>   how many delegations one client may hold at a
//	                       time. Defaults to 4.
//
// Nothing in DHCPv6 authenticates a client, so what one datagram can claim is
// capped throughout: at most maxIAPDsPerMessage IA_PD options are answered,
// one DUID holds at most max-prefixes delegations, and a DUID longer than RFC
// 8415 §11.1 allows is dropped rather than used as a lease-map key.
package prefix

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

var log = logger.GetLogger("plugins/prefix")

// Plugin registers the prefix. Prefix delegation only exists for DHCPv6
var Plugin = plugins.Plugin{
	Name:   "prefix",
	Setup6: setupPrefix,
}

const (
	sweepArg = "sweep"

	maxPrefixesArg = "max-prefixes"

	optionSyntax = sweepArg + ":<duration> or " + maxPrefixesArg + ":<count>"

	defaultLeaseDuration = time.Hour

	// A short lease duration must not turn the sweeper into a hot loop taking
	// the plugin lock.
	minSweepInterval = 30 * time.Second

	// A home router asks for one; four leaves room for a site that genuinely
	// subnets behind itself without letting one DUID walk off with the pool.
	defaultMaxPrefixes = 4

	// More IA_PDs than any client legitimately asks for at once, and few
	// enough that the reply still fits in a datagram.
	maxIAPDsPerMessage = 8

	// The 128 octets RFC 8415 §11.1 allows, plus the two-octet type code the
	// wire form recordKey keys on carries in front of them.
	maxDUIDLength = 130
)

type lease struct {
	Prefix net.IPNet
	Expire time.Time
}

func (l lease) expired(t time.Time) bool {
	return !l.Expire.After(t)
}

// Two prefix plugins in one config carve from their own pool and keep their
// own leases.
type pluginState struct {
	sync.Mutex
	// Keyed by the DUID's wire form as a string. It is not valid UTF-8, so no
	// string function may be used on it.
	Records   map[string][]lease
	allocator allocators.Allocator

	// Set during setup, read-only afterwards.
	leaseDuration time.Duration
	sweepInterval time.Duration
	maxPrefixes   int

	name       string
	poolRange  string
	poolBlocks int

	// Clock seam. Read it through timeNow: a zero-valued pluginState leaves
	// it nil.
	now func() time.Time

	// Nothing in the server stops a plugin, so these exist only so tests can
	// reap the sweeper instead of leaking one goroutine per test.
	stop chan struct{}
	done chan struct{}
}

func (h *pluginState) timeNow() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

// The empty prefix is equal to nothing, not even itself.
func samePrefix(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func recordKey(d dhcpv6.DUID) string {
	return string(d.ToBytes())
}

// Handle processes DHCPv6 packets for the prefix plugin.
func (h *pluginState) Handle(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Error(err)
		return nil, true
	}

	client := msg.Options.ClientID()
	if client == nil {
		log.Error("Invalid packet received, no clientID")
		return nil, true
	}
	if n := len(client.ToBytes()); n > maxDUIDLength {
		log.Infof("Dropping %s: client DUID is %d octets, over the %d RFC 8415 §11.1 allows", msg.MessageType, n, maxDUIDLength)
		return nil, true
	}

	switch msg.MessageType {
	case dhcpv6.MessageTypeRelease:
		h.handleRelease(client, msg, resp)
		return resp, false
	case dhcpv6.MessageTypeDecline:
		// RFC 8415 §18.3.8: DECLINE applies to IA_NA and IA_TA only, so a
		// delegating router has nothing to do with it.
		return resp, false
	}

	for _, iapd := range iapdsToAnswer(msg) {
		resp.AddOption(h.respondToIAPD(client, iapd))
	}

	return resp, false
}

// The surplus is ignored rather than answered with a status: the point is to
// keep the reply from growing with whatever the sender put in the request.
func iapdsToAnswer(msg *dhcpv6.Message) []*dhcpv6.OptIAPD {
	iapds := msg.Options.IAPD()
	if len(iapds) <= maxIAPDsPerMessage {
		return iapds
	}
	log.Debugf("Ignoring %d IA_PD option(s) past the first %d in one %s", len(iapds)-maxIAPDsPerMessage, maxIAPDsPerMessage, msg.MessageType)
	return iapds[:maxIAPDsPerMessage]
}

// RFC 8415 §18.3.7: every IA_PD in the message gets one back carrying a Status
// Code, and the Reply itself carries Success.
func (h *pluginState) handleRelease(client dhcpv6.DUID, msg *dhcpv6.Message, resp dhcpv6.DHCPv6) {
	h.Lock()
	defer h.Unlock()

	key := recordKey(client)
	for _, iapd := range iapdsToAnswer(msg) {
		resp.AddOption(h.releaseIAPD(key, iapd))
	}
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "prefixes released",
	})
}

// Leases carry no IAID, so a binding exists only if the IA_PD lists a prefix
// this client holds; an empty IA_PD therefore also gets NoBinding. That status
// is left textless (RFC 8415 §21.13 makes text optional) because a sender can
// ask for it endlessly, and text turns the reply into a reflector. Caller
// holds h's lock.
func (h *pluginState) releaseIAPD(key string, iapd *dhcpv6.OptIAPD) *dhcpv6.OptIAPD {
	answer := &dhcpv6.OptIAPD{IaId: iapd.IaId}
	if h.releasePrefixes(key, iapd.Options.Prefixes()) == 0 {
		log.Debugf("No binding to release for IAID %x", iapd.IaId)
		answer.Options.Add(&dhcpv6.OptStatusCode{StatusCode: dhcpIana.StatusNoBinding})
		return answer
	}
	answer.Options.Add(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "prefixes released",
	})
	return answer
}

// A prefix the client does not hold is left alone: a release names the
// sender's own bindings, never somebody else's. Caller holds h's lock.
func (h *pluginState) releasePrefixes(key string, released []*dhcpv6.OptIAPrefix) int {
	known := h.Records[key]
	// Filtering into known[:0] reuses the backing array: it only ever writes
	// at or below the index being read, so nothing unvisited is clobbered.
	live, freed := known[:0], 0
	for _, l := range known {
		if !listed(released, l) {
			live = append(live, l)
			continue
		}
		h.free(l)
		freed++
	}
	h.store(key, live)
	return freed
}

func listed(released []*dhcpv6.OptIAPrefix, l lease) bool {
	for _, p := range released {
		if samePrefix(p.Prefix, &l.Prefix) {
			return true
		}
	}
	return false
}

// A failure is logged rather than propagated: nothing in the exchange can act
// on it, and the alternative is keeping a lease we no longer honour.
func (h *pluginState) free(l lease) {
	if err := h.allocator.Free(l.Prefix); err != nil {
		log.Errorf("Could not return prefix %s to the pool: %v", &l.Prefix, err)
	}
}

// The map entry goes when a client holds nothing: empty slices left behind
// would let one-off clients grow the map without bound. Caller holds h's lock.
func (h *pluginState) store(key string, leases []lease) {
	if len(leases) == 0 {
		delete(h.Records, key)
		return
	}
	h.Records[key] = leases
}

// The lapsed prefixes are carried for the length of one exchange so a client
// coming back late can be hinted its old prefix. Caller holds h's lock.
func (h *pluginState) dropExpired(key string, t time.Time) ([]lease, []net.IPNet) {
	known := h.Records[key]
	// See releasePrefixes for why filtering into known[:0] is safe.
	live := known[:0]
	var recovered []net.IPNet
	for _, l := range known {
		if !l.expired(t) {
			live = append(live, l)
			continue
		}
		h.free(l)
		recovered = append(recovered, l.Prefix)
	}
	return live, recovered
}

// The caller must hold h's lock.
func (h *pluginState) sweepExpired(t time.Time) int {
	var freed int
	for key := range h.Records {
		live, recovered := h.dropExpired(key, t)
		freed += len(recovered)
		h.store(key, live)
	}
	return freed
}

func (h *pluginState) sweepOnce() {
	h.Lock()
	defer h.Unlock()
	if freed := h.sweepExpired(h.timeNow()); freed > 0 {
		log.Printf("Returned %d expired prefix delegation(s) to the pool", freed)
	}
}

// The loop lives for the lifetime of the process; h.stop is there for tests.
func (h *pluginState) startSweeper(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(h.done)
		for {
			select {
			case <-h.stop:
				return
			case <-ticker.C:
				h.sweepOnce()
			}
		}
	}()
}

// Nothing in the server calls this; it keeps tests from leaking a goroutine.
func (h *pluginState) stopSweeper() {
	close(h.stop)
	<-h.done
}

// A request we could not satisfy at all still gets an IA_PD back, carrying a
// status code instead of prefixes.
func (h *pluginState) respondToIAPD(client dhcpv6.DUID, iapd *dhcpv6.OptIAPD) *dhcpv6.OptIAPD {
	iapdResp := &dhcpv6.OptIAPD{
		IaId: iapd.IaId,
	}

	h.reconcile(client, iapd, iapdResp)

	if len(iapdResp.Options.Options) == 0 {
		log.Debugf("No valid prefix to return for IAID %x", iapd.IaId)
		iapdResp.Options.Add(&dhcpv6.OptStatusCode{
			StatusCode: dhcpIana.StatusNoPrefixAvail,
		})
	}

	return iapdResp
}

// An IA_PD without any IAPrefix is still a valid request, so it gets one empty
// hint. Wire-level nil prefixes (the decoder returns nil for a zero prefix
// length) are normalised to the same empty prefix here, in one place, so no
// nil reaches the matching passes.
func requestedPrefixes(iapd *dhcpv6.OptIAPD) []*dhcpv6.OptIAPrefix {
	hints := iapd.Options.Prefixes()
	if len(hints) == 0 {
		return []*dhcpv6.OptIAPrefix{{Prefix: &net.IPNet{}}}
	}
	for _, hint := range hints {
		if hint.Prefix == nil {
			hint.Prefix = &net.IPNet{}
		}
	}
	return hints
}

// satisfied is indexed by position in hints, givenOut by position in
// knownLeases, which aliases the slice in pluginState.Records -- pushing an
// expiry out in place is what renews a lease. recovered holds prefixes this
// client held until they lapsed, offered back before any unrelated block.
type pdExchange struct {
	client        dhcpv6.DUID
	iaid          [4]byte
	now           time.Time
	leaseDuration time.Duration
	hints         []*dhcpv6.OptIAPrefix
	knownLeases   []lease
	recovered     []net.IPNet
	satisfied     *bitset.BitSet
	givenOut      *bitset.BitSet
	resp          *dhcpv6.OptIAPD
}

// Three heuristic passes in order of decreasing confidence, all under the lock
// because they renew leases in place and may append to the client's record.
// Lapsed leases are dropped first: one past its expiry must never be renewed
// and handed back as valid, so it goes to the pool and is re-allocated by hint.
func (h *pluginState) reconcile(client dhcpv6.DUID, iapd, iapdResp *dhcpv6.OptIAPD) {
	hints := requestedPrefixes(iapd)

	h.Lock()
	defer h.Unlock()

	now := h.timeNow()
	key := recordKey(client)
	knownLeases, recovered := h.dropExpired(key, now)

	e := &pdExchange{
		client:        client,
		iaid:          iapd.IaId,
		now:           now,
		leaseDuration: h.leaseDuration,
		hints:         hints,
		knownLeases:   knownLeases,
		recovered:     recovered,
		satisfied:     bitset.New(uint(len(hints))),
		givenOut:      bitset.New(uint(len(knownLeases))),
		resp:          iapdResp,
	}

	e.renewExactMatches()
	e.giveOutRemaining()
	h.store(key, h.allocateForUnsatisfied(e))
}

// The safest heuristic: an exact match cannot be a better fit for some other
// hint in the same request.
func (e *pdExchange) renewExactMatches() {
	for hintIdx, hint := range e.hints {
		for leaseIdx := range e.knownLeases {
			if samePrefix(hint.Prefix, &e.knownLeases[leaseIdx].Prefix) {
				e.grant(hintIdx, leaseIdx)
			}
		}
	}
}

// A hint is never taken out of the running once served, so one unqualified
// hint can absorb every remaining lease.
func (e *pdExchange) giveOutRemaining() {
	for hintIdx, hint := range e.hints {
		if !e.wantsAnyPrefix(hintIdx, hint) {
			continue
		}
		for leaseIdx, l := range e.knownLeases {
			if e.givenOut.Test(uint(leaseIdx)) || !lengthMatches(hint, l) {
				continue
			}
			e.grant(hintIdx, leaseIdx)
		}
	}
}

// A client says "any prefix" by hinting at the all-zeroes address. The empty
// hint synthesised for an IA_PD with no IAPrefix has no address at all, so it
// does not qualify and falls through to a fresh allocation.
func (e *pdExchange) wantsAnyPrefix(hintIdx int, hint *dhcpv6.OptIAPrefix) bool {
	if e.satisfied.Test(uint(hintIdx)) {
		return false
	}
	return hint.Prefix.IP.Equal(net.IPv6zero)
}

// A hint that named no length takes any lease. hint.Prefix is never nil here:
// requestedPrefixes normalises wire-level nil prefixes at the edge.
func lengthMatches(hint *dhcpv6.OptIAPrefix, l lease) bool {
	hintPrefixLen, _ := hint.Prefix.Mask.Size()
	if hintPrefixLen == 0 {
		return true
	}
	leasePrefixLen, _ := l.Prefix.Mask.Size()
	return hintPrefixLen == leasePrefixLen
}

// The expiry is pushed out to a full lease duration, never shortening a lease
// that already runs longer.
func (e *pdExchange) grant(hintIdx, leaseIdx int) {
	expire := e.now.Add(e.leaseDuration)
	if e.knownLeases[leaseIdx].Expire.Before(expire) {
		e.knownLeases[leaseIdx].Expire = expire
	}
	e.satisfied.Set(uint(hintIdx))
	e.givenOut.Set(uint(leaseIdx))
	addPrefix(e.resp, e.knownLeases[leaseIdx], e.now)
}

// The accumulator starts from the known leases so a lease allocated for an
// earlier hint of the same request survives, and so its length measures the
// per-client limit: prefixes already held count towards it, which is what
// makes the limit hold across several IA_PDs and several messages.
func (h *pluginState) allocateForUnsatisfied(e *pdExchange) []lease {
	newLeases := e.knownLeases

	for hintIdx, hint := range e.hints {
		if e.satisfied.Test(uint(hintIdx)) {
			continue
		}
		if len(newLeases) >= h.maxPrefixes {
			log.Debugf("Client %s already holds %d prefix(es), not delegating another (IAID: %x)", e.client, len(newLeases), e.iaid)
			continue
		}

		l, ok := h.newLease(e.allocationHint(hint), e.now, e.leaseDuration)
		if !ok {
			continue
		}

		addPrefix(e.resp, l, e.now)
		newLeases = append(newLeases, l)
		log.Debugf("Allocated %s to %s (IAID: %x)", &l.Prefix, e.client, e.iaid)
	}

	return newLeases
}

// A hint the client actually named wins; otherwise a prefix it held until its
// lease lapsed is offered back, so a returning client keeps what it had.
func (e *pdExchange) allocationHint(hint *dhcpv6.OptIAPrefix) net.IPNet {
	if len(e.recovered) == 0 || !unspecified(hint) {
		return *hint.Prefix
	}
	recovered := e.recovered[0]
	e.recovered = e.recovered[1:]
	return recovered
}

// A hint that named a length keeps it, so a returning client is never handed
// back a prefix of a size it did not ask for.
func unspecified(hint *dhcpv6.OptIAPrefix) bool {
	if length, _ := hint.Prefix.Mask.Size(); length != 0 {
		return false
	}
	return len(hint.Prefix.IP) == 0 || hint.Prefix.IP.Equal(net.IPv6zero)
}

// False is not fatal to the request as a whole: the other hints may still be
// satisfiable.
func (h *pluginState) newLease(hint net.IPNet, now time.Time, leaseDuration time.Duration) (lease, bool) {
	allocated, err := h.allocator.Allocate(hint)
	if err != nil {
		log.Debugf("Nothing allocated for hinted prefix %s", &hint)
		return lease{}, false
	}

	return lease{
		Expire: now.Add(leaseDuration),
		Prefix: allocated,
	}, true
}

func addPrefix(resp *dhcpv6.OptIAPD, l lease, now time.Time) {
	lifetime := l.Expire.Sub(now)

	resp.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: lifetime,
		ValidLifetime:     lifetime,
		Prefix:            dup(&l.Prefix),
	})
}

func dup(src *net.IPNet) (dst *net.IPNet) {
	dst = &net.IPNet{
		IP:   make(net.IP, net.IPv6len),
		Mask: make(net.IPMask, net.IPv6len),
	}
	copy(dst.IP, src.IP)
	copy(dst.Mask, src.Mask)
	return dst
}

// Half a lease, so a prefix is back in the pool well within one lease of
// lapsing.
func defaultSweepInterval(leaseDuration time.Duration) time.Duration {
	if half := leaseDuration / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// The lease duration is the last positional argument and everything after it
// is named key:value, so an argument carrying a colon means it was left out.
func parseLeaseDuration(extra []string) (time.Duration, []string, error) {
	if len(extra) == 0 || strings.Contains(extra[0], ":") {
		return defaultLeaseDuration, extra, nil
	}
	duration, err := time.ParseDuration(extra[0])
	if err != nil {
		return 0, nil, fmt.Errorf("invalid lease duration %q: %w", extra[0], err)
	}
	if duration <= 0 {
		return 0, nil, fmt.Errorf("lease duration has to be positive, got: %v", extra[0])
	}
	return duration, extra[1:], nil
}

type pluginOptions struct {
	sweepInterval time.Duration
	maxPrefixes   int
}

var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:       parseSweepInterval,
	maxPrefixesArg: parseMaxPrefixes,
}

// An unknown or repeated key is an error rather than quietly ignored: a typo
// must not leave the operator with a default they believe they overrode.
func parseOptions(leaseDuration time.Duration, extra []string) (pluginOptions, error) {
	opts := pluginOptions{
		sweepInterval: defaultSweepInterval(leaseDuration),
		maxPrefixes:   defaultMaxPrefixes,
	}
	seen := make(map[string]bool, len(extra))
	for _, arg := range extra {
		key, value, hasValue := strings.Cut(arg, ":")
		parse, known := optionParsers[key]
		if !hasValue || !known {
			return pluginOptions{}, fmt.Errorf("unexpected argument %q, want %s", arg, optionSyntax)
		}
		if seen[key] {
			return pluginOptions{}, fmt.Errorf("argument %s given more than once", key)
		}
		seen[key] = true
		if err := parse(&opts, value); err != nil {
			return pluginOptions{}, err
		}
	}
	return opts, nil
}

func parseSweepInterval(opts *pluginOptions, raw string) error {
	interval, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid sweep interval %q: %w", raw, err)
	}
	if interval <= 0 {
		return fmt.Errorf("sweep interval has to be positive, got: %v", raw)
	}
	opts.sweepInterval = interval
	return nil
}

// Zero is refused rather than read as "no delegations at all": an operator who
// wants that leaves the plugin out of the config.
func parseMaxPrefixes(opts *pluginOptions, raw string) error {
	count, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("invalid prefix maximum %q: %w", raw, err)
	}
	if count < 1 {
		return fmt.Errorf("prefix maximum has to be positive, got: %v", raw)
	}
	opts.maxPrefixes = count
	return nil
}

func setupPrefix(args ...string) (handler.Handler6, error) {
	h, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Both come after everything that can fail: no goroutine sweeping a
	// half-built plugin, no half-built instance visible to a lease reader.
	h.startSweeper(h.sweepInterval)
	leases.Register(h)
	log.Printf("Delegating at most %d prefix(es) per client for %s, reclaiming expired ones every %s", h.maxPrefixes, h.leaseDuration, h.sweepInterval)
	return h.Handle, nil
}

// The instance comes back idle, with no sweeper, so tests that own the
// goroutine's lifetime can call this directly.
func newPluginState(args ...string) (*pluginState, error) {
	if len(args) < 2 {
		return nil, errors.New("need both a subnet and an allocation max size")
	}

	_, prefix, err := net.ParseCIDR(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid pool subnet: %w", err)
	}
	// The allocator carves 128-bit prefixes out of whatever it is given, so an
	// IPv4 pool would pass setup and fail every allocation at runtime.
	if prefix.IP.To4() != nil {
		return nil, fmt.Errorf("pool subnet %q is not IPv6", args[0])
	}

	allocSize, err := strconv.Atoi(args[1])
	if err != nil || allocSize > 128 || allocSize < 0 {
		return nil, fmt.Errorf("invalid prefix length: %w", err)
	}

	leaseDuration, rest, err := parseLeaseDuration(args[2:])
	if err != nil {
		return nil, err
	}
	opts, err := parseOptions(leaseDuration, rest)
	if err != nil {
		return nil, err
	}

	alloc, err := bitmap.NewBitmapAllocator(*prefix, allocSize)
	if err != nil {
		return nil, fmt.Errorf("could not initialize prefix allocator: %w", err)
	}

	poolLen, _ := prefix.Mask.Size()
	return &pluginState{
		Records:       make(map[string][]lease),
		allocator:     alloc,
		leaseDuration: leaseDuration,
		sweepInterval: opts.sweepInterval,
		maxPrefixes:   opts.maxPrefixes,
		name:          "prefix " + args[0],
		poolRange:     prefix.String(),
		poolBlocks:    poolBlocks(poolLen, allocSize),
		now:           time.Now,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}, nil
}
