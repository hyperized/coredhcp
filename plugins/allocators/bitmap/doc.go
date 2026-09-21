// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package bitmap allocates addresses and prefixes by keeping one bit per
// allocatable unit. It holds the three implementations of
// [github.com/coredhcp/coredhcp/plugins/allocators].Allocator that the
// pool plugins use: IPv4Allocator for single IPv4 addresses, IPv6Allocator
// for single IPv6 addresses, and Allocator for delegated IPv6 prefixes.
// None of them is a plugin and none reads configuration; the plugin passes
// what the operator wrote to the constructor.
//
// All three cost memory in proportion to the size of the pool rather than
// to the number of clients, one bit each, and all three are safe for
// concurrent use: every method takes the allocator's own mutex, since the
// bitset underneath is not goroutine-safe. None of them persists anything.
// A restart begins with every bit clear, and the plugin replays its lease
// database through Allocate to get back where it was.
//
// # IPv4Allocator
//
//	NewIPv4Allocator(start, end net.IP) (*IPv4Allocator, error)
//
// Hands out single addresses from the inclusive range [start, end], which
// is what the range plugin is configured with. Both arguments have to be
// IPv4, and start must not be above end; either mistake is an error
// naming the range plugin's arguments. One bit per address puts a /16 at
// 8KiB and a /8 at 2MiB, so the practical limit is the operator's patience
// rather than a hard bound.
//
// # IPv6Allocator
//
//	NewIPv6Allocator(start, end net.IP) (*IPv6Allocator, error)
//	(*IPv6Allocator).Size() uint64
//
// The same thing for single IPv6 addresses out of an inclusive range, used
// by the range6 plugin. Both arguments have to be IPv6 and not IPv4: an
// IPv4-mapped address is refused rather than quietly widened. The range
// may hold at most 2^32 addresses, which makes a /96 the widest pool and
// caps the bitmap at 512MiB; a wider range is an error telling the
// operator to narrow it. Size reports how many addresses the pool holds,
// which is what the plugin bounds its lease table against.
//
// An IPv6 pool is where a bit per address stops being free, and it is why
// the cap exists at all. The full space below a /64 is not something any
// bitmap can represent.
//
// # Allocator
//
//	NewBitmapAllocator(pool net.IPNet, size int) (*Allocator, error)
//
// Carves /size prefixes out of pool for the prefix plugin to delegate, one
// bit per prefix. Every block is the same size no matter what the client
// asked for, which reduces prefix delegation to the single-address problem
// the other two solve. That is what Kea does as well, and it is a
// reasonable trade whenever the pool is much larger than the number of
// clients expected.
//
// size is a prefix length and must be at least the pool's own, since a /48
// pool cannot hand out a /32. The gap between the two lengths must also
// stay below strconv.IntSize, 64 on a 64-bit build, which puts the ceiling
// at 2^63 prefixes; that is a bound on what the index type can address
// rather than on what any machine could hold. Both are startup errors that
// name the prefix length argument. From 2^32 prefixes upward the
// constructor warns instead of refusing: it works, at 512MiB of bitmap and
// climbing.
//
// Allocate always reserves exactly one prefix of the configured size. The
// mask on the returned block is that size too, unless the hint asked for
// something smaller and carried a full 128-bit mask, in which case the
// hint's length comes back over the prefix that was reserved.
//
// # Hints
//
// All three take the hint the same way. A hint that names a free block
// inside the pool is honoured; anything else falls back to the first free
// block the bitmap can find, scanning from the start of the pool. The two
// single-address allocators go one step further and ignore the error from
// an unusable hint entirely, so a client offering a hint from some other
// network, or none at all, is simply tried against the first address in
// the range before the scan begins.
//
// # Errors
//
// Allocate returns allocators.ErrNoAddrAvail when the pool is full, and
// Free returns *allocators.ErrDoubleFree for a block that was not
// allocated. Those two are the errors a caller can match on. Everything
// else is about a bad argument: an address that is not of the right
// family, or one outside the pool. Those errors are unexported and worded
// for the operator reading the log, naming the plugin argument to fix.
// IPv4Allocator.Free reports both causes with the same error, while its
// IPv6 sibling keeps them apart.
package bitmap
