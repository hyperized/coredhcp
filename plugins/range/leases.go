// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"math"
	"net/netip"
	"time"

	"github.com/coredhcp/coredhcp/leases"
)

// This file implements leases.Source over the same state the packet path uses,
// under the same lock.

// Name reports this instance as "range <lease file>", which is what
// distinguishes two range plugins in one configuration.
func (p *pluginState) Name() string {
	return p.name
}

// Leases returns every lease this instance currently holds.
//
// A lease that has expired but not been swept yet is included with its past
// expiry: hiding it would show an address as free while its allocator bit is
// still set. The slice is the caller's to keep.
func (p *pluginState) Leases() []leases.Lease {
	p.Lock()
	defer p.Unlock()

	out := make([]leases.Lease, 0, len(p.Recordsv4))
	for mac, record := range p.Recordsv4 {
		addr, ok := netip.AddrFromSlice(record.IP.To4())
		if !ok {
			// Unreachable: every address in the map came from the IPv4
			// allocator. Skipping beats serving an invalid address.
			continue
		}
		out = append(out, leases.Lease{
			Family: 4,
			Client: mac,
			// UTC because an API answer is usually read somewhere other than
			// the host that produced it.
			Expires:  time.Unix(int64(record.expires), 0).UTC(),
			Address:  netip.PrefixFrom(addr, addr.BitLen()),
			Hostname: record.hostname,
			Source:   p.name,
		})
	}
	return out
}

// Pools returns the one pool this instance allocates from.
//
// Used and Quarantined are disjoint, and both sit inside Size.
func (p *pluginState) Pools() []leases.Pool {
	p.Lock()
	defer p.Unlock()

	return []leases.Pool{{
		Source:      p.name,
		Family:      4,
		Range:       p.poolRange,
		Size:        poolSizeAsInt(p.poolSize),
		Used:        len(p.Recordsv4),
		Quarantined: len(p.declined),
	}}
}

// Saturates rather than wraps: 2^32 addresses do not fit in the int of a
// 32-bit build, and a negative pool size breaks whatever reads it.
func poolSizeAsInt(size uint64) int {
	if size > math.MaxInt {
		return math.MaxInt
	}
	return int(size)
}
