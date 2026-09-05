// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package prefix implements a plugin offering prefixes to clients requesting
// them with IA_PREFIX requests.
//
// The plugin takes the pool and the allocation size, and optionally a lease
// duration and a sweep interval:
//
//	server6:
//	  plugins:
//	    - prefix: 2001:db8::/48 64 1h sweep:30m
//
// The pool is the base prefix that assigned prefixes are carved from. The
// allocation size is the largest prefix handed to a client: one asking for
// something bigger gets a prefix of this size. The lease duration defaults to
// 1h. sweep:<duration> sets how often lapsed delegations are reclaimed in the
// background, and defaults to half the lease duration, floored at 30s.
//
// Delegations used to be handed out and never taken back. The expiry was
// written and pushed out on renewal, but nothing read it and the allocator was
// never asked to free anything, so a pool of 65536 /64s served 70000 clients
// and then served nobody, with the lease map still holding every client that
// had ever asked. Prefixes now go back to the pool from two places: the
// background sweeper, and the request path for the client in front of us.
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
	// sweepArgPrefix marks the optional trailing argument that overrides the
	// background sweep interval, e.g. "sweep:5m".
	sweepArgPrefix = "sweep:"

	// defaultLeaseDuration is what a delegation lasts when the config does not
	// say. It is the value this plugin hardcoded before the argument existed.
	defaultLeaseDuration = time.Hour

	// minSweepInterval floors the derived sweep interval, so a short lease
	// duration does not turn the sweeper into a hot loop taking the plugin
	// lock.
	minSweepInterval = 30 * time.Second
)

type lease struct {
	Prefix net.IPNet
	Expire time.Time
}

// expired reports whether the lease had already lapsed at t.
func (l lease) expired(t time.Time) bool {
	return !l.Expire.After(t)
}

// pluginState holds the pool and the lease set of a single setup6 instance of
// the plugin. Two prefix plugins in the same config carve from their own pool
// and keep their own leases.
type pluginState struct {
	// Mutex here is the simplest implementation fit for purpose.
	// We can revisit for perf when we move lease management to separate plugins
	sync.Mutex
	// Records has a string'd []byte as key, because []byte can't be a key itself
	// Since it's not valid utf-8 we can't use any other string function though
	Records   map[string][]lease
	allocator allocators.Allocator

	// leaseDuration is how long a delegation lasts, sweepInterval how often
	// lapsed ones are reclaimed in the background. Both are set during setup
	// and read-only afterwards.
	leaseDuration time.Duration
	sweepInterval time.Duration

	// now is the clock seam. It is written once during setup, before the
	// sweeper goroutine starts, and only read afterwards. Use timeNow rather
	// than calling it directly: a zero-valued pluginState leaves it nil.
	now func() time.Time

	// stop closes to shut the background sweeper down; done closes once it has
	// exited. The server never stops a plugin, so nothing closes stop in
	// production. It exists so tests can reap the goroutine deterministically
	// instead of leaking one per test.
	stop chan struct{}
	done chan struct{}
}

// timeNow reads the clock through the seam, falling back to time.Now so a
// zero-valued pluginState still works.
func (h *pluginState) timeNow() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

// samePrefix returns true if both prefixes are defined and equal
// The empty prefix is equal to nothing, not even itself
func samePrefix(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

// recordKey computes the key for the Records array from the client ID
func recordKey(d dhcpv6.DUID) string {
	return string(d.ToBytes())
}

// Handle processes DHCPv6 packets for the prefix plugin for a given allocator/leaseset
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

	switch msg.MessageType {
	case dhcpv6.MessageTypeRelease:
		h.handleRelease(client, msg, resp)
		return resp, false
	case dhcpv6.MessageTypeDecline:
		// RFC 8415 §18.3.8: DECLINE reports an address the client found
		// already in use, and applies to IA_NA and IA_TA only. There is
		// nothing for a delegating router to do with one, so the message
		// passes to the next plugin without an IA_PD.
		return resp, false
	}

	// Each request IA_PD requires an IA_PD response
	for _, iapd := range msg.Options.IAPD() {
		resp.AddOption(h.respondToIAPD(client, iapd))
	}

	return resp, false
}

// handleRelease frees the prefixes a RELEASE lists and answers per RFC 8415
// §18.3.7: every IA_PD in the message gets one back carrying a Status Code,
// and the Reply itself carries Success. The response is then handed on rather
// than ending the chain, because a lease hook or a DDNS plugin further down
// still has to see the release.
func (h *pluginState) handleRelease(client dhcpv6.DUID, msg *dhcpv6.Message, resp dhcpv6.DHCPv6) {
	h.Lock()
	defer h.Unlock()

	key := recordKey(client)
	for _, iapd := range msg.Options.IAPD() {
		resp.AddOption(h.releaseIAPD(key, iapd))
	}
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "prefixes released",
	})
}

// releaseIAPD frees the prefixes of one released IA_PD and builds the answer
// for it.
//
// Leases carry no IAID of their own, so "do we have a binding for this IA_PD"
// can only be answered by whether any prefix it lists is one this client
// holds. An IA_PD listing no prefixes at all therefore also gets NoBinding,
// which is the answer that stops a client retrying. The caller must hold h's
// lock.
func (h *pluginState) releaseIAPD(key string, iapd *dhcpv6.OptIAPD) *dhcpv6.OptIAPD {
	answer := &dhcpv6.OptIAPD{IaId: iapd.IaId}
	if h.releasePrefixes(key, iapd.Options.Prefixes()) == 0 {
		log.Debugf("No binding to release for IAID %x", iapd.IaId)
		answer.Options.Add(&dhcpv6.OptStatusCode{
			StatusCode:    dhcpIana.StatusNoBinding,
			StatusMessage: "no prefix bound to this IAID",
		})
		return answer
	}
	answer.Options.Add(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "prefixes released",
	})
	return answer
}

// releasePrefixes frees whichever of the listed prefixes this client actually
// holds and reports how many went back to the pool. A prefix the client does
// not hold is left alone: a release names the sender's own bindings, and must
// not free somebody else's. The caller must hold h's lock.
func (h *pluginState) releasePrefixes(key string, released []*dhcpv6.OptIAPrefix) int {
	known := h.Records[key]
	// Filtering into known[:0] reuses the backing array. It only ever writes
	// at an index at or below the one being read, so the entries still to be
	// visited are never clobbered.
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

// listed reports whether one of the released prefixes names lease l.
func listed(released []*dhcpv6.OptIAPrefix, l lease) bool {
	for _, p := range released {
		if samePrefix(p.Prefix, &l.Prefix) {
			return true
		}
	}
	return false
}

// free returns a prefix to the pool. A failure is logged rather than
// propagated: nothing in the exchange can act on it, and the alternative is
// holding on to a lease we have already stopped honouring.
func (h *pluginState) free(l lease) {
	if err := h.allocator.Free(l.Prefix); err != nil {
		log.Errorf("Could not return prefix %s to the pool: %v", &l.Prefix, err)
	}
}

// store writes a client's lease set back, dropping the map entry when the
// client is left holding nothing. Leaving empty slices behind would let a
// population of one-off clients grow the map without bound. The caller must
// hold h's lock.
func (h *pluginState) store(key string, leases []lease) {
	if len(leases) == 0 {
		delete(h.Records, key)
		return
	}
	h.Records[key] = leases
}

// dropExpired returns a client's live leases and the prefixes of the ones that
// had lapsed at t, which it frees on the way through.
//
// The lapsed prefixes are worth carrying for the length of one exchange: a
// client that comes back late gets its old prefix hinted back at the allocator
// and keeps it as long as nobody else took it, which is what range's
// reallocateExpired does for addresses. The caller must hold h's lock.
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

// sweepExpired frees every lapsed delegation, forgets the clients left holding
// nothing, and reports how many prefixes went back to the pool. The caller
// must hold h's lock.
func (h *pluginState) sweepExpired(t time.Time) int {
	var freed int
	for key := range h.Records {
		live, recovered := h.dropExpired(key, t)
		freed += len(recovered)
		h.store(key, live)
	}
	return freed
}

// sweepOnce takes the lock and reclaims every lapsed delegation.
func (h *pluginState) sweepOnce() {
	h.Lock()
	defer h.Unlock()
	if freed := h.sweepExpired(h.timeNow()); freed > 0 {
		log.Printf("Returned %d expired prefix delegation(s) to the pool", freed)
	}
}

// startSweeper runs the background reclamation loop. It lives for the lifetime
// of the process, since plugins are never stopped or unregistered, but it
// still honours h.stop so tests can shut it down.
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

// stopSweeper shuts the background sweeper down and waits for it to exit.
// Nothing in the server calls this; it exists so a test does not leave a
// goroutine running after it finishes.
func (h *pluginState) stopSweeper() {
	close(h.stop)
	<-h.done
}

// respondToIAPD builds the IA_PD option answering one requested IA_PD. A request
// we could not satisfy at all still gets an IA_PD back, carrying a status code
// instead of prefixes.
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

// requestedPrefixes returns the prefixes the client hints at in one IA_PD.
// An IA_PD without any IAPrefix is still a valid request (just unspecified) and
// we must attempt to allocate a prefix for it, so it gets a single empty hint,
// which is equivalent to no hint. A hint whose prefix is absent on the wire
// (the decoder returns nil for a zero prefix-length) is normalised to the same
// empty prefix here, in one place: letting nil flow deeper used to crash the
// handler as soon as the client already held a lease.
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

// pdExchange is the working state of one IA_PD reconciliation: the requests
// (prefix hints asked by the client), what is on offer (the leases we already
// hold for it), the bookkeeping of what has been matched to what, and the
// response being filled in.
//
// satisfied is indexed by position in hints, givenOut by position in
// knownLeases. knownLeases aliases the slice held in pluginState.Records, so
// pushing out an expiry in place is what renews a lease. recovered holds the
// prefixes this client held until its leases lapsed, offered back to the
// allocator before any unrelated block is.
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

// reconcile matches the hints of one IA_PD against the leases we already hold
// for this client, plus new blocks from the pool, and adds every prefix the
// client ends up with to iapdResp.
//
// The matching is, for now, a set of heuristics, run as three passes in order of
// decreasing confidence. The whole thing runs under the lock: the passes renew
// leases in place and may append to the client's record.
//
// Lapsed leases are dropped before any of it. A lease past its expiry must
// never be renewed and handed back as if it were valid; it goes back to the
// pool first and is then re-allocated like any other request, hinting at the
// prefix the client used to have.
func (h *pluginState) reconcile(client dhcpv6.DUID, iapd, iapdResp *dhcpv6.OptIAPD) {
	hints := requestedPrefixes(iapd)

	// A possible simple optimization here would be to be able to lock single map values
	// individually instead of the whole map, since we lock for some amount of time
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

// renewExactMatches extends the leases that exactly match a hint and hands them
// straight back.
//
// This is the safest heuristic, if the lease matches exactly we know we aren't
// missing assigning it to a better candidate request.
func (e *pdExchange) renewExactMatches() {
	for hintIdx, hint := range e.hints {
		for leaseIdx := range e.knownLeases {
			if samePrefix(hint.Prefix, &e.knownLeases[leaseIdx].Prefix) {
				e.grant(hintIdx, leaseIdx)
			}
		}
	}
}

// giveOutRemaining satisfies the hints that named no particular prefix with the
// leases this client already holds and that no hint has claimed yet.
//
// A hint is never taken out of the running once it has been served, so one
// unqualified hint can absorb every remaining lease. That is the historical
// behaviour, pinned by TestHandleZeroIPHintLengthMismatchAllocatesNew.
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

// wantsAnyPrefix reports whether a hint still needs a prefix and takes whichever
// one we care to give it, which a client says by hinting at the all-zeroes
// address.
//
// The empty hint we synthesise for an IA_PD that carried no IAPrefix at all has
// no address rather than the zero address, so it does not qualify here and falls
// through to a fresh allocation.
func (e *pdExchange) wantsAnyPrefix(hintIdx int, hint *dhcpv6.OptIAPrefix) bool {
	if e.satisfied.Test(uint(hintIdx)) {
		return false
	}
	return hint.Prefix.IP.Equal(net.IPv6zero)
}

// lengthMatches reports whether lease l has the prefix length hint asked for.
// A hint that named no length takes any lease. hint.Prefix is never nil here:
// requestedPrefixes normalises wire-level nil prefixes at the edge.
//
// This is a bad heuristic depending on the allocator behavior, to be improved.
func lengthMatches(hint *dhcpv6.OptIAPrefix, l lease) bool {
	hintPrefixLen, _ := hint.Prefix.Mask.Size()
	if hintPrefixLen == 0 {
		return true
	}
	leasePrefixLen, _ := l.Prefix.Mask.Size()
	return hintPrefixLen == leasePrefixLen
}

// grant hands the lease at leaseIdx to the hint at hintIdx: it pushes the expiry
// out to a full lease duration, never shortening a lease that already runs
// longer, marks both sides as accounted for, and adds the prefix to the response.
func (e *pdExchange) grant(hintIdx, leaseIdx int) {
	expire := e.now.Add(e.leaseDuration)
	if e.knownLeases[leaseIdx].Expire.Before(expire) {
		e.knownLeases[leaseIdx].Expire = expire
	}
	e.satisfied.Set(uint(hintIdx))
	e.givenOut.Set(uint(leaseIdx))
	addPrefix(e.resp, e.knownLeases[leaseIdx], e.now)
}

// allocateForUnsatisfied carves a new prefix out of the pool for every hint no
// existing lease could satisfy, and returns the client's full lease set.
//
// What is left at this point are requests with a hint we can't trivially satisfy,
// and possibly expired leases that haven't been explicitly requested again.
// A possible improvement here would be to try to widen existing leases, to
// satisfy wider requests that contain an existing lease; and to try to break down
// existing leases into smaller allocations, to satisfy requests for a subnet of an
// existing lease. We probably don't need such complex behavior (the vast majority
// of requests will come with an empty, or length-only hint)
//
// The accumulator starts from the known leases so that a lease allocated for an
// earlier hint of the same request survives (7f79c14).
func (h *pluginState) allocateForUnsatisfied(e *pdExchange) []lease {
	newLeases := e.knownLeases

	for hintIdx, hint := range e.hints {
		if e.satisfied.Test(uint(hintIdx)) {
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

// allocationHint decides what to ask the allocator for. A hint the client
// actually named wins. Otherwise a prefix this client held until its lease
// lapsed is offered back, so a client returning after a gap keeps the prefix it
// had as long as nobody else took it in the meantime.
func (e *pdExchange) allocationHint(hint *dhcpv6.OptIAPrefix) net.IPNet {
	if len(e.recovered) == 0 || !unspecified(hint) {
		return *hint.Prefix
	}
	recovered := e.recovered[0]
	e.recovered = e.recovered[1:]
	return recovered
}

// unspecified reports whether a hint asks for nothing in particular: neither an
// address nor a length. A hint that named a length keeps it, so a returning
// client is never handed back a prefix of a size it did not ask for.
func unspecified(hint *dhcpv6.OptIAPrefix) bool {
	if length, _ := hint.Prefix.Mask.Size(); length != 0 {
		return false
	}
	return len(hint.Prefix.IP) == 0 || hint.Prefix.IP.Equal(net.IPv6zero)
}

// newLease carves a prefix out of the pool for a single hint. It reports false
// when the allocator has nothing to offer, which is not fatal to the request as
// a whole: the other hints may still be satisfiable.
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

// defaultSweepInterval derives the sweep period from the lease duration: half a
// lease, so a prefix is back in the pool well within one lease of lapsing,
// floored at minSweepInterval.
func defaultSweepInterval(leaseDuration time.Duration) time.Duration {
	if half := leaseDuration / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// parseLeaseDuration reads the optional third positional argument and returns
// it along with whatever came after it. The argument is positional and the
// sweep argument is named, so an extra argument that already looks like a sweep
// argument means the lease duration was left out.
func parseLeaseDuration(extra []string) (time.Duration, []string, error) {
	if len(extra) == 0 || strings.HasPrefix(extra[0], sweepArgPrefix) {
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

// parseSweepInterval reads the optional trailing "sweep:<duration>" argument,
// falling back to defaultSweepInterval. Anything that is not a sweep argument
// is rejected rather than silently ignored.
func parseSweepInterval(leaseDuration time.Duration, extra []string) (time.Duration, error) {
	if len(extra) == 0 {
		return defaultSweepInterval(leaseDuration), nil
	}
	if len(extra) > 1 {
		return 0, fmt.Errorf("too many arguments, want at most 4 (pool, allocation size, lease duration, %s<duration>), got %d", sweepArgPrefix, len(extra)+2)
	}
	raw, ok := strings.CutPrefix(extra[0], sweepArgPrefix)
	if !ok {
		return 0, fmt.Errorf("unexpected argument %q, want %s<duration>", extra[0], sweepArgPrefix)
	}
	interval, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid sweep interval %q: %w", raw, err)
	}
	if interval <= 0 {
		return 0, fmt.Errorf("sweep interval has to be positive, got: %v", raw)
	}
	return interval, nil
}

// setupPrefix builds the plugin instance and starts its background sweeper.
func setupPrefix(args ...string) (handler.Handler6, error) {
	h, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Started only once setup has fully succeeded: a failed setup must not
	// leave a goroutine behind sweeping a half-built plugin.
	h.startSweeper(h.sweepInterval)
	log.Printf("Delegating prefixes for %s, reclaiming expired ones every %s", h.leaseDuration, h.sweepInterval)
	return h.Handle, nil
}

// newPluginState validates the plugin arguments and builds a ready but idle
// instance: no sweeper is running yet. setupPrefix starts it; tests that need
// to own the goroutine's lifetime call this directly.
func newPluginState(args ...string) (*pluginState, error) {
	// - prefix: 2001:db8::/48 64 1h sweep:30m
	if len(args) < 2 {
		return nil, errors.New("need both a subnet and an allocation max size")
	}

	_, prefix, err := net.ParseCIDR(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid pool subnet: %w", err)
	}

	allocSize, err := strconv.Atoi(args[1])
	if err != nil || allocSize > 128 || allocSize < 0 {
		return nil, fmt.Errorf("invalid prefix length: %w", err)
	}

	leaseDuration, rest, err := parseLeaseDuration(args[2:])
	if err != nil {
		return nil, err
	}
	sweepInterval, err := parseSweepInterval(leaseDuration, rest)
	if err != nil {
		return nil, err
	}

	// TODO: select allocators based on heuristics or user configuration
	alloc, err := bitmap.NewBitmapAllocator(*prefix, allocSize)
	if err != nil {
		return nil, fmt.Errorf("could not initialize prefix allocator: %w", err)
	}

	return &pluginState{
		Records:       make(map[string][]lease),
		allocator:     alloc,
		leaseDuration: leaseDuration,
		sweepInterval: sweepInterval,
		now:           time.Now,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}, nil
}
