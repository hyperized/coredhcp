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

// This file makes an instance of the range plugin readable: it implements
// leases.Source over the same state the packet path uses, under the same lock,
// so an API or a UI can list what the pool has handed out. setupRange
// registers the instance; see plugin.go.

// Name reports this instance as "range <lease file>", which is what
// distinguishes two range plugins in one configuration.
func (p *pluginState) Name() string {
	return p.name
}

// Leases returns every lease this instance currently holds.
//
// The list is built under the plugin lock and handed over, so the caller can
// take as long as it likes with it while the packet path carries on. A lease
// that has expired but has not been swept yet is included, carrying the expiry
// that has already passed: hiding it would leave an address that reads as free
// while the allocator still has its bit set, which is the confusing half of
// exactly the bug this fork's sweeper fixes.
func (p *pluginState) Leases() []leases.Lease {
	p.Lock()
	defer p.Unlock()

	out := make([]leases.Lease, 0, len(p.Recordsv4))
	for mac, record := range p.Recordsv4 {
		addr, ok := netip.AddrFromSlice(record.IP.To4())
		if !ok {
			// Every address in the map came from the IPv4 allocator, so this
			// is unreachable in production. Skipping beats serving a lease
			// with an invalid address in it.
			continue
		}
		out = append(out, leases.Lease{
			Family: 4,
			Client: mac,
			// Expiry is stored as a Unix second. It goes out in UTC because
			// an API answer is usually read somewhere other than the host
			// that produced it.
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
// Used counts the leases handed out, Quarantined the addresses a client
// declined and that are held back from the pool without being leased to
// anyone. The two are disjoint, and both sit inside Size.
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

// poolSizeAsInt narrows the pool size for reporting, saturating instead of
// wrapping.
//
// A range covering the whole address space holds 2^32 addresses, which does
// not fit in the 32 bits an int has on a 32-bit build (a Raspberry Pi Zero is
// a deployment target here). Reporting the largest int is wrong by a factor
// nobody will notice; reporting a negative pool size is wrong in a way that
// breaks whatever reads it.
func poolSizeAsInt(size uint64) int {
	if size > math.MaxInt {
		return math.MaxInt
	}
	return int(size)
}
