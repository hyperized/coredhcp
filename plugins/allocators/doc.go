// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package allocators is the interface the pool plugins hand out addresses
// through, together with the address arithmetic that goes with it. It is a
// library rather than a plugin: nothing here is named in a configuration
// file, and there is nothing to configure.
//
// The problem it solves has many parallels with memory allocation. A pool
// is a block of address space, clients take pieces of it and give them
// back, and the allocator's whole job is to know which pieces are free.
//
// # The interface
//
// Allocator has two methods, both taking a net.IPNet so that a single
// address and a delegated prefix are described the same way.
//
//	Allocate(hint net.IPNet) (net.IPNet, error)
//	Free(net.IPNet) error
//
// hint is what the client asked for, and it is only a hint. An allocator
// may hand it over when it happens to be free, and should return a block
// of the size the hint asked for, but it must not report an error just
// because it gave out something else. A caller that needs the exact block
// compares what came back against what it asked for, which is what the
// range plugin does when it replays a stored lease.
//
// Free returns a block to the pool. It takes the block as it was handed
// out; an implementation is free to mask the address down to the prefix
// itself.
//
// Nothing here knows about leases. Expiry, persistence, and deciding that
// a client is gone all belong to the plugin holding the allocator, and an
// allocator only ever forgets a block because someone called Free. The
// range and range6 plugins replay their stored leases through Allocate at
// startup for exactly that reason: the bitmap starts empty on every run.
//
// # Errors
//
// Three errors are exported, and they are the only ones a caller can match
// on.
//
//   - ErrNoAddrAvail comes back from Allocate when every block in the pool
//     is taken. Match it with errors.Is.
//   - ErrDoubleFree comes back from Free when the block was not
//     allocated. It is a struct type rather than a sentinel, carrying the
//     block in Loc, so match it with errors.As on a *ErrDoubleFree.
//   - ErrOverflow comes from the arithmetic below, when a result leaves
//     the 128-bit address space.
//
// Implementations wrap these, so compare with errors.Is and errors.As
// rather than by value.
//
// # Address arithmetic
//
// Offset and AddPrefixes convert between an address and its index in an
// allocator's table, which is what lets a bitmap stand in for a pool.
//
//	Offset(a, b net.IP, prefixLength int) (uint64, error)
//	AddPrefixes(ip net.IP, n, unit uint64) (net.IP, error)
//
// Offset is the distance between two addresses counted in /prefixLength
// subnets, with anything finer than that mask discarded. AddPrefixes is
// the inverse: the nth /unit subnet after a base address. Go has no
// 128-bit integer, so both work on the address as a pair of uint64 halves.
//
// Offset rejects a prefix length outside 0 to 128, and returns ErrOverflow
// when the two addresses are more than 2^64 units apart. AddPrefixes needs
// a 16-byte address, an IPv4 one widened with To16 included, and returns
// ErrOverflow when the result would carry past the top of the address
// space.
//
// # Implementations and callers
//
// The [github.com/coredhcp/coredhcp/plugins/allocators/bitmap] subpackage
// holds the three implementations in the tree, one bit per allocatable
// unit each. The range plugin builds a bitmap.IPv4Allocator, range6 a
// bitmap.IPv6Allocator, and prefix a bitmap.Allocator for delegation. The
// subnet plugin builds a range or prefix instance per subnet, so it uses
// them one step removed.
package allocators
