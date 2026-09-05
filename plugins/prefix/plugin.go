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
// Delegations used to be handed out and never taken back. The expiry was
// written and pushed out on renewal, but nothing read it and the allocator was
// never asked to free anything, so a pool of 65536 /64s served 70000 clients
// and then served nobody, with the lease map still holding every client that
// had ever asked. Prefixes now go back to the pool from two places: the
// background sweeper, and the request path for the client in front of us.
//
// # What one packet may cost
//
// Nothing in DHCPv6 authenticates a client, so the work and the addresses one
// datagram can claim are all capped.
//
// A message is answered for at most maxIAPDsPerMessage IA_PD options. Every
// IA_PD in a message used to be served: a 146-byte SOLICIT carrying eight of
// them emptied a /62 pool of four /64s, and roughly 4096 fit in a full
// datagram, at which point the reply grew too large to send and the sender
// paid nothing at all.
//
// One client, meaning one DUID, holds at most max-prefixes delegations. An
// IA_PD that would take it past that is answered with NoPrefixAvail rather
// than served, which is the same answer an exhausted pool gives.
//
// A client DUID longer than RFC 8415 §11.1 allows is dropped, since the lease
// map is keyed by the DUID's wire form and would otherwise grow by whatever a
// sender cared to put in the option.
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
	// sweepArg names the optional argument that overrides the background sweep
	// interval, e.g. "sweep:5m".
	sweepArg = "sweep"

	// maxPrefixesArg names the optional argument that overrides how many
	// delegations one client may hold, e.g. "max-prefixes:8".
	maxPrefixesArg = "max-prefixes"

	// optionSyntax spells the named arguments out for error messages.
	optionSyntax = sweepArg + ":<duration> or " + maxPrefixesArg + ":<count>"

	// defaultLeaseDuration is what a delegation lasts when the config does not
	// say. It is the value this plugin hardcoded before the argument existed.
	defaultLeaseDuration = time.Hour

	// minSweepInterval floors the derived sweep interval, so a short lease
	// duration does not turn the sweeper into a hot loop taking the plugin
	// lock.
	minSweepInterval = 30 * time.Second

	// defaultMaxPrefixes is how many delegations one client may hold unless
	// the config says otherwise. A home router asks for one, and four leaves
	// room for a site that genuinely subnets behind itself without letting a
	// single DUID walk off with a pool.
	defaultMaxPrefixes = 4

	// maxIAPDsPerMessage caps how many IA_PD options one message is answered
	// for. Eight is more than any client legitimately asks for in one go, and
	// low enough that the reply still fits in a datagram.
	maxIAPDsPerMessage = 8

	// maxDUIDLength is the longest client DUID this plugin will key its lease
	// map on: the 128 octets RFC 8415 §11.1 allows, plus the two-octet type
	// code that the wire form recordKey uses carries in front of them.
	maxDUIDLength = 130
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
	// lapsed ones are reclaimed in the background, and maxPrefixes how many
	// delegations one client may hold. All three are set during setup and
	// read-only afterwards.
	leaseDuration time.Duration
	sweepInterval time.Duration
	maxPrefixes   int

	// name identifies this instance to a lease reader, poolRange spells the
	// pool out for one, and poolBlocks is how many prefixes of the
	// allocation size the pool holds. All three are built during setup and
	// read-only afterwards; see leases.go.
	name       string
	poolRange  string
	poolBlocks int

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
	if n := len(client.ToBytes()); n > maxDUIDLength {
		log.Infof("Dropping %s: client DUID is %d octets, over the %d RFC 8415 §11.1 allows", msg.MessageType, n, maxDUIDLength)
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
	for _, iapd := range iapdsToAnswer(msg) {
		resp.AddOption(h.respondToIAPD(client, iapd))
	}

	return resp, false
}

// iapdsToAnswer returns the IA_PD options of msg that will be answered, at
// most maxIAPDsPerMessage of them. The rest are ignored rather than answered
// with a status, because the point is to keep the reply from growing with
// whatever the sender put in the request.
func iapdsToAnswer(msg *dhcpv6.Message) []*dhcpv6.OptIAPD {
	iapds := msg.Options.IAPD()
	if len(iapds) <= maxIAPDsPerMessage {
		return iapds
	}
	log.Debugf("Ignoring %d IA_PD option(s) past the first %d in one %s", len(iapds)-maxIAPDsPerMessage, maxIAPDsPerMessage, msg.MessageType)
	return iapds[:maxIAPDsPerMessage]
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
	for _, iapd := range iapdsToAnswer(msg) {
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
//
// NoBinding carries no message text. It is the one status a sender can ask
// for over and over, by releasing prefixes it never held, and RFC 8415 §21.13
// leaves the text optional. Text there made the reply grow to three times the
// request, which is a reflector anyone on the segment can point somewhere.
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
// earlier hint of the same request survives (7f79c14). Its length is also what
// the per-client limit is measured against: leases already held count towards
// it, which is what makes the limit hold across several IA_PDs in one message
// and across several messages.
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
// it along with whatever came after it. The lease duration is the last
// positional argument and everything after it is named key:value, so an
// argument carrying a colon means the lease duration was left out. A duration
// never contains one.
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

// pluginOptions holds the settings taken from the named key:value arguments
// that may follow the positional ones.
type pluginOptions struct {
	sweepInterval time.Duration
	maxPrefixes   int
}

// optionParsers dispatches on the argument key. parseOptions handles ordering,
// duplicates and unknown keys for every entry here, so accepting another
// argument is one line plus its parser.
var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:       parseSweepInterval,
	maxPrefixesArg: parseMaxPrefixes,
}

// parseOptions reads the named key:value arguments, which may come in any
// order. extra holds whatever followed the lease duration. An unknown key, or
// a key given twice, is an error rather than something quietly ignored: a typo
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

// parseSweepInterval reads the value of a "sweep:" argument.
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

// parseMaxPrefixes reads the value of a "max-prefixes:" argument. Zero is
// refused rather than read as "no delegations at all": an operator who wants
// that leaves the plugin out of the config.
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

// setupPrefix builds the plugin instance and starts its background sweeper.
func setupPrefix(args ...string) (handler.Handler6, error) {
	h, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Started only once setup has fully succeeded: a failed setup must not
	// leave a goroutine behind sweeping a half-built plugin.
	h.startSweeper(h.sweepInterval)
	// Registered last, once everything that could fail has succeeded: a
	// reader must never find a half-built instance in the registry.
	leases.Register(h)
	log.Printf("Delegating at most %d prefix(es) per client for %s, reclaiming expired ones every %s", h.maxPrefixes, h.leaseDuration, h.sweepInterval)
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
	// Prefix delegation is DHCPv6 only. An IPv4 pool used to pass setup and
	// then fail every allocation at runtime, because the allocator carves
	// 128-bit prefixes out of whatever it is given.
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

	// TODO: select allocators based on heuristics or user configuration
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
