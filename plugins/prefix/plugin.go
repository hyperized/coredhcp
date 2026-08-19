// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package prefix implements a plugin offering prefixes to clients requesting them
// This plugin attributes prefixes to clients requesting them with IA_PREFIX requests.
//
// Arguments for the plugin configuration are as follows, in this order:
// - prefix: The base prefix from which assigned prefixes are carved
// - max: maximum size of the prefix delegated to clients. When a client requests a larger prefix
// than this, this is the size of the offered prefix
package prefix

// FIXME: various settings will be hardcoded (default size, minimum size, lease times) pending a
// better configuration system

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
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

const leaseDuration = 3600 * time.Second

func setupPrefix(args ...string) (handler.Handler6, error) {
	// - prefix: 2001:db8::/48 64
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

	// TODO: select allocators based on heuristics or user configuration
	alloc, err := bitmap.NewBitmapAllocator(*prefix, allocSize)
	if err != nil {
		return nil, fmt.Errorf("could not initialize prefix allocator: %w", err)
	}

	return (&pluginState{
		Records:   make(map[string][]lease),
		allocator: alloc,
	}).Handle, nil
}

type lease struct {
	Prefix net.IPNet
	Expire time.Time
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

	// Each request IA_PD requires an IA_PD response
	for _, iapd := range msg.Options.IAPD() {
		resp.AddOption(h.respondToIAPD(client, iapd))
	}

	return resp, false
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
// which is equivalent to no hint.
func requestedPrefixes(iapd *dhcpv6.OptIAPD) []*dhcpv6.OptIAPrefix {
	hints := iapd.Options.Prefixes()
	if len(hints) == 0 {
		return []*dhcpv6.OptIAPrefix{{Prefix: &net.IPNet{}}}
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
// pushing out an expiry in place is what renews a lease.
type pdExchange struct {
	client      dhcpv6.DUID
	iaid        [4]byte
	hints       []*dhcpv6.OptIAPrefix
	knownLeases []lease
	satisfied   *bitset.BitSet
	givenOut    *bitset.BitSet
	resp        *dhcpv6.OptIAPD
}

// reconcile matches the hints of one IA_PD against the leases we already hold
// for this client, plus new blocks from the pool, and adds every prefix the
// client ends up with to iapdResp.
//
// The matching is, for now, a set of heuristics, run as three passes in order of
// decreasing confidence. The whole thing runs under the lock: the passes renew
// leases in place and may append to the client's record.
func (h *pluginState) reconcile(client dhcpv6.DUID, iapd, iapdResp *dhcpv6.OptIAPD) {
	hints := requestedPrefixes(iapd)

	// A possible simple optimization here would be to be able to lock single map values
	// individually instead of the whole map, since we lock for some amount of time
	h.Lock()
	defer h.Unlock()

	knownLeases := h.Records[recordKey(client)]
	e := &pdExchange{
		client:      client,
		iaid:        iapd.IaId,
		hints:       hints,
		knownLeases: knownLeases,
		satisfied:   bitset.New(uint(len(hints))),
		givenOut:    bitset.New(uint(len(knownLeases))),
		resp:        iapdResp,
	}

	e.renewExactMatches()
	e.giveOutRemaining()
	newLeases := h.allocateForUnsatisfied(e)

	if len(newLeases) != len(knownLeases) {
		h.Records[recordKey(client)] = newLeases
	}
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
	return hint.Prefix == nil || hint.Prefix.IP.Equal(net.IPv6zero)
}

// lengthMatches reports whether lease l has the prefix length hint asked for.
// A hint that named no length takes any lease.
//
// This is a bad heuristic depending on the allocator behavior, to be improved.
//
// hint.Prefix is read without a nil check, which is the behaviour that was here
// before: a hint with no prefix at all (which the wire decoder produces for a
// prefix-length of 0) panics here as soon as the client holds a lease we have
// not given out yet. Left as-is to keep this refactor behaviour-preserving; it
// wants a fix of its own.
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
	expire := time.Now().Add(leaseDuration)
	if e.knownLeases[leaseIdx].Expire.Before(expire) {
		e.knownLeases[leaseIdx].Expire = expire
	}
	e.satisfied.Set(uint(hintIdx))
	e.givenOut.Set(uint(leaseIdx))
	addPrefix(e.resp, e.knownLeases[leaseIdx])
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

		l, ok := h.newLease(hint)
		if !ok {
			continue
		}

		addPrefix(e.resp, l)
		newLeases = append(newLeases, l)
		log.Debugf("Allocated %s to %s (IAID: %x)", &l.Prefix, e.client, e.iaid)
	}

	return newLeases
}

// newLease carves a prefix out of the pool for a single hint. It reports false
// when the allocator has nothing to offer, which is not fatal to the request as
// a whole: the other hints may still be satisfiable.
//
// A hint with no prefix at all is normalised to the empty prefix in place, which
// the allocator reads as "anything will do".
func (h *pluginState) newLease(hint *dhcpv6.OptIAPrefix) (lease, bool) {
	if hint.Prefix == nil {
		hint.Prefix = &net.IPNet{}
	}

	allocated, err := h.allocator.Allocate(*hint.Prefix)
	if err != nil {
		log.Debugf("Nothing allocated for hinted prefix %s", hint)
		return lease{}, false
	}

	return lease{
		Expire: time.Now().Add(leaseDuration),
		Prefix: allocated,
	}, true
}

func addPrefix(resp *dhcpv6.OptIAPD, l lease) {
	lifetime := time.Until(l.Expire)

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
