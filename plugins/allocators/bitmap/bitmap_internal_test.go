// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

import (
	"math"
	"math/rand"
	"net"
	"testing"

	"github.com/bits-and-blooms/bitset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFreeToIndexError exercises the wrapped error path in both toIndex and
// Free: a page length outside the valid prefix range (0-128) makes the
// underlying allocators.Offset call fail. The exported constructor never
// produces such an Allocator, so it's built by hand here.
func TestFreeToIndexError(t *testing.T) {
	pool := net.IPNet{IP: net.ParseIP("2001:db8::").To16(), Mask: net.CIDRMask(48, 128)}
	alloc := &Allocator{
		containing: pool,
		page:       200, // out of the 0-128 range accepted by allocators.Offset
		bitmap:     bitset.New(4),
	}

	_, err := alloc.toIndex(pool.IP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot compute prefix index")

	err = alloc.Free(net.IPNet{IP: pool.IP, Mask: net.CIDRMask(200, 128)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not find prefix in pool")
}

// TestAllocateToPrefixBug exercises the defensive "BUG" branch in Allocate:
// an index that the bitmap considers free but that toPrefix can't turn back
// into a valid prefix. page=0 makes allocators.AddPrefixes fail for any
// non-zero index (unit==0 && n!=0 => ErrOverflow), so pre-occupying bit 0
// forces the next allocation to hit index 1.
func TestAllocateToPrefixBug(t *testing.T) {
	pool := net.IPNet{IP: net.ParseIP("2001:db8::").To16(), Mask: net.CIDRMask(48, 128)}
	alloc := &Allocator{
		containing: pool,
		page:       0,
		bitmap:     bitset.New(4),
	}
	alloc.bitmap.Set(0)

	_, err := alloc.Allocate(net.IPNet{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BUG: could not get prefix from allocation")

	// the failed allocation must roll back the bitmap so the index isn't leaked
	assert.False(t, alloc.bitmap.Test(1))
}

func getAllocator(tb testing.TB, bits int) *Allocator {
	tb.Helper()
	_, prefix, err := net.ParseCIDR("2001:db8::/56")
	require.NoError(tb, err)
	alloc, err := NewBitmapAllocator(*prefix, 56+bits)
	require.NoError(tb, err)

	return alloc
}

func prefixSizeForAllocs(allocs int) int {
	return int(math.Ceil(math.Log2(float64(allocs))))
}

func BenchmarkParallelAllocPartiallyFilled(b *testing.B) {
	// We'll make a bitmap with 2x the number of allocs we want to make.
	// Then randomly fill it to about 50% utilization
	alloc := getAllocator(b, prefixSizeForAllocs(b.N)+1)

	// Build a replacement bitmap that we'll put in the allocator, with approx. 50% of values filled
	newbmap := make([]uint64, alloc.bitmap.Len())
	for i := uint(0); i < alloc.bitmap.Len(); i++ {
		newbmap[i] = rand.Uint64()
	}
	alloc.bitmap = bitset.From(newbmap)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if n, err := alloc.Allocate(net.IPNet{}); err != nil {
				b.Logf("Could not allocate (got %v and an error): %v", n, err)
				b.Fail()
			}
		}
	})
}
