// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"encoding/hex"
	"math"
	"net"
	"net/netip"
	"strconv"

	"github.com/coredhcp/coredhcp/leases"
)

// This file makes an instance of the prefix plugin readable: it implements
// leases.Source over the same state the packet path uses, under the same lock,
// so an API or a UI can list the delegations outstanding. setupPrefix
// registers the instance; see plugin.go.

// Name reports this instance as "prefix <pool>", which is what distinguishes
// two prefix plugins in one configuration.
func (h *pluginState) Name() string {
	return h.name
}

// Leases returns every delegation this instance currently holds.
//
// One client holding several prefixes appears once per prefix. The IAID is not
// part of a Lease here because this plugin does not keep one: Records is keyed
// by DUID alone, and a client's prefixes are matched back to its IA_PDs by
// prefix, not by identity association.
//
// A delegation whose lease has lapsed but that the sweeper has not reclaimed
// yet is included, with the expiry that has already passed.
func (h *pluginState) Leases() []leases.Lease {
	h.Lock()
	defer h.Unlock()

	out := make([]leases.Lease, 0, len(h.Records))
	for key, held := range h.Records {
		// The map key is the DUID's wire form used as a string, which is not
		// text: hex is the form a reader can match against a packet capture.
		client := hex.EncodeToString([]byte(key))
		for _, l := range held {
			prefix, ok := asPrefix(l.Prefix)
			if !ok {
				// Every prefix here came out of the allocator, so this is
				// unreachable in production. Skipping beats serving a lease
				// with an invalid prefix in it.
				continue
			}
			out = append(out, leases.Lease{
				Family: 6,
				Client: client,
				// UTC because an API answer is usually read somewhere other
				// than the host that produced it.
				Expires: l.Expire.UTC(),
				Address: prefix,
				Source:  h.name,
			})
		}
	}
	return out
}

// Pools returns the one pool this instance delegates from.
//
// Used counts prefixes rather than clients, matching Size, which counts the
// blocks of the allocation size the pool holds. Nothing is ever quarantined: a
// DECLINE says an address is already in use on the link and has no meaning for
// a delegated prefix, so this plugin ignores those messages entirely.
func (h *pluginState) Pools() []leases.Pool {
	h.Lock()
	defer h.Unlock()

	var used int
	for _, held := range h.Records {
		used += len(held)
	}
	return []leases.Pool{{
		Source: h.name,
		Family: 6,
		Range:  h.poolRange,
		Size:   h.poolBlocks,
		Used:   used,
	}}
}

// asPrefix converts an allocated block to a netip.Prefix.
func asPrefix(n net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones), true
}

// poolBlocks counts the prefixes of the allocation size that fit in a pool of
// poolLen bits, saturating instead of overflowing.
//
// The allocator has already refused anything outside 0 <= allocSize-poolLen <
// strconv.IntSize by the time a pool exists, so the only order that reaches the
// cap here is the largest one, where 1<<order would land on the sign bit and
// report a negative pool.
func poolBlocks(poolLen, allocSize int) int {
	order := allocSize - poolLen
	if order >= strconv.IntSize-1 {
		return math.MaxInt
	}
	return 1 << order
}
