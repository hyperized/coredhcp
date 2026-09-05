// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"net/netip"
	"time"

	"github.com/coredhcp/coredhcp/leases"
)

// Name reports this instance as "range6 <lease file>".
func (p *pluginState) Name() string {
	return p.name
}

// Leases returns every binding, expired but unswept ones included: their
// address is still held in the allocator.
func (p *pluginState) Leases() []leases.Lease {
	p.Lock()
	defer p.Unlock()

	out := make([]leases.Lease, 0, len(p.Records6))
	for _, record := range p.Records6 {
		addr, ok := netip.AddrFromSlice(record.IP.To16())
		if !ok {
			// Unreachable: every address in the map came from the allocator.
			continue
		}
		out = append(out, leases.Lease{
			Family:   6,
			Client:   hex.EncodeToString(record.DUID),
			IAID:     binary.BigEndian.Uint32(record.IAID[:]),
			Expires:  time.Unix(int64(record.expires), 0).UTC(),
			Address:  netip.PrefixFrom(addr, addr.BitLen()),
			Hostname: record.hostname,
			Source:   p.name,
		})
	}
	return out
}

// Pools returns the one pool this instance allocates from; Used and Quarantined are disjoint.
func (p *pluginState) Pools() []leases.Pool {
	p.Lock()
	defer p.Unlock()

	return []leases.Pool{{
		Source:      p.name,
		Family:      6,
		Range:       p.poolRange,
		Size:        poolSizeAsInt(p.poolSize),
		Used:        len(p.Records6),
		Quarantined: len(p.declined),
	}}
}

// poolSizeAsInt saturates rather than wraps: a 2^32 pool does not fit an int on 32-bit builds.
func poolSizeAsInt(size uint64) int {
	if size > math.MaxInt {
		return math.MaxInt
	}
	return int(size)
}
