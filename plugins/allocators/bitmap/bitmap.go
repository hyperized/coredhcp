// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/bits-and-blooms/bitset"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/allocators"
)

var log = logger.GetLogger("plugins/allocators/bitmap")

// Allocator is a prefix allocator allocating in chunks of a fixed size
// regardless of the size requested by the client.
// It consumes an amount of memory proportional to the total amount of available prefixes
type Allocator struct {
	containing net.IPNet
	page       int
	bitmap     *bitset.BitSet
	l          sync.Mutex
}

// prefix must verify: containing.Mask.Size < prefix.Mask.Size < page
func (a *Allocator) toIndex(base net.IP) (uint, error) {
	value, err := allocators.Offset(base, a.containing.IP, a.page)
	if err != nil {
		return 0, fmt.Errorf("cannot compute prefix index for %s in pool %s: %w; check the pool subnet in the plugin's arguments", base, a.containing.String(), err)
	}

	return uint(value), nil
}

func (a *Allocator) toPrefix(idx uint) (net.IP, error) {
	// page is a prefix length: non-negative and at most 128, set at construction.
	return allocators.AddPrefixes(a.containing.IP, uint64(idx), uint64(a.page)) //nolint:gosec // see above
}

// Allocate reserves a maxsize-sized block and returns a block of size
// min(maxsize, hint.size)
func (a *Allocator) Allocate(hint net.IPNet) (ret net.IPNet, err error) {
	// Ensure size is max(maxsize, hint.size)
	reqSize, hintErr := hint.Mask.Size()
	if reqSize < a.page || hintErr != 128 {
		reqSize = a.page
	}
	ret.Mask = net.CIDRMask(reqSize, 128)

	// Try to allocate the requested prefix
	a.l.Lock()
	defer a.l.Unlock()
	if hint.IP.To16() != nil && a.containing.Contains(hint.IP) {
		idx, hintErr := a.toIndex(hint.IP)
		if hintErr == nil && !a.bitmap.Test(idx) {
			a.bitmap.Set(idx)
			ret.IP, err = a.toPrefix(idx)
			return ret, err
		}
	}

	// Find a free prefix
	next, ok := a.bitmap.NextClear(0)
	if !ok {
		err = allocators.ErrNoAddrAvail
		return ret, err
	}
	a.bitmap.Set(next)
	ret.IP, err = a.toPrefix(next)
	if err != nil {
		// This violates the assumption that every index in the bitmap maps back to a valid prefix
		err = fmt.Errorf("BUG: could not get prefix from allocation: %w; report this with the pool subnet and prefix length the plugin was given", err)
		a.bitmap.Clear(next)
	}
	return ret, err
}

// Free returns the given prefix to the available pool if it was taken.
func (a *Allocator) Free(prefix net.IPNet) error {
	idx, err := a.toIndex(prefix.IP.Mask(prefix.Mask))
	if err != nil {
		return fmt.Errorf("could not find prefix in pool: %w", err)
	}

	a.l.Lock()
	defer a.l.Unlock()

	if !a.bitmap.Test(idx) {
		return &allocators.ErrDoubleFree{Loc: prefix}
	}
	a.bitmap.Clear(idx)
	return nil
}

// NewBitmapAllocator creates a new allocator, allocating /`size` prefixes
// carved out of the given `pool` prefix
func NewBitmapAllocator(pool net.IPNet, size int) (*Allocator, error) {
	poolSize, _ := pool.Mask.Size()
	allocOrder := size - poolSize

	switch {
	case allocOrder < 0:
		return nil, fmt.Errorf("the size of allocated prefixes cannot be larger than the pool they're allocated from: /%d is wider than /%d; set the prefix length argument to %d or more", size, poolSize, poolSize)
	case allocOrder >= strconv.IntSize:
		return nil, fmt.Errorf("a pool with more than 2^%d items is not representable on this platform; use a prefix length below /%d", allocOrder, poolSize+strconv.IntSize)
	case allocOrder >= 32:
		log.Warningf("the pool holds 2^%d prefixes, one bitmap bit each; lower the prefix length argument to carve fewer, wider prefixes if memory runs short", allocOrder)
	}

	// A bitset can always hold 1<<allocOrder items here: Cap() is the max
	// uint, and allocOrder was bounded below strconv.IntSize above.

	alloc := Allocator{
		containing: pool,
		page:       size,

		bitmap: bitset.New(1 << uint(allocOrder)),
	}

	return &alloc, nil
}
