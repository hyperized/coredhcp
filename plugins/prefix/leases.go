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

// This file implements leases.Source over the same state the packet path uses,
// under the same lock.

// Name reports this instance as "prefix <pool>", which is what distinguishes
// two prefix plugins in one configuration.
func (h *pluginState) Name() string {
	return h.name
}

// Leases returns every delegation this instance currently holds.
//
// One client holding several prefixes appears once per prefix, without an
// IAID: Records is keyed by DUID alone. A lapsed but unswept delegation is
// included, carrying the expiry that has already passed.
func (h *pluginState) Leases() []leases.Lease {
	h.Lock()
	defer h.Unlock()

	out := make([]leases.Lease, 0, len(h.Records))
	for key, held := range h.Records {
		// The key is the DUID's wire form, not text: hex is what a reader can
		// match against a packet capture.
		client := hex.EncodeToString([]byte(key))
		for _, l := range held {
			prefix, ok := asPrefix(l.Prefix)
			if !ok {
				// Unreachable: every prefix here came out of the allocator.
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
// Used and Size both count blocks of the allocation size, not clients. Nothing
// is ever quarantined: DECLINE has no meaning for a delegated prefix.
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

func asPrefix(n net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones), true
}

// Saturates rather than overflows: the allocator has already refused every
// order but the largest, where 1<<order would land on the sign bit and report
// a negative pool.
func poolBlocks(poolLen, allocSize int) int {
	order := allocSize - poolLen
	if order >= strconv.IntSize-1 {
		return math.MaxInt
	}
	return 1 << order
}
