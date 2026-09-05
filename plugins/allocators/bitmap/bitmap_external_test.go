// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap_test

import (
	"math"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

func getAllocator(t *testing.T, bits int) *bitmap.Allocator {
	t.Helper()
	_, prefix, err := net.ParseCIDR("2001:db8::/56")
	require.NoError(t, err)
	alloc, err := bitmap.NewBitmapAllocator(*prefix, 56+bits)
	require.NoError(t, err)

	return alloc
}

func TestAllocateAndDoubleFree(t *testing.T) {
	alloc := getAllocator(t, 8)

	prefix, err := alloc.Allocate(net.IPNet{})
	require.NoError(t, err)

	require.NoError(t, alloc.Free(prefix))

	err = alloc.Free(prefix)
	require.Error(t, err, "expected DoubleFree error")
	var dfErr *allocators.ErrDoubleFree
	assert.ErrorAs(t, err, &dfErr)
}

func TestExhaustAndReallocateAfterFree(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8::/62")
	require.NoError(t, err)
	alloc, err := bitmap.NewBitmapAllocator(*prefix, 64)
	require.NoError(t, err)

	allocd := []net.IPNet{}
	for range 4 {
		n, err := alloc.Allocate(net.IPNet{Mask: net.CIDRMask(64, 128)})
		require.NoError(t, err, "should not fail before exhaustion")
		allocd = append(allocd, n)
	}

	_, err = alloc.Allocate(net.IPNet{})
	assert.ErrorIs(t, err, allocators.ErrNoAddrAvail)

	require.NoError(t, alloc.Free(allocd[1]))

	n, err := alloc.Allocate(allocd[1])
	require.NoError(t, err, "could not reallocate after free")
	assert.True(t, n.IP.Equal(allocd[1].IP))
	assert.Equal(t, allocd[1].Mask.String(), n.Mask.String())
}

func TestAllocateWithHintOutsidePool(t *testing.T) {
	alloc := getAllocator(t, 8)
	_, prefix, err := net.ParseCIDR("fe80:abcd::/48")
	require.NoError(t, err)

	res, err := alloc.Allocate(*prefix)
	require.NoError(t, err, "failed to allocate with invalid hint")

	prefLen, totalLen := res.Mask.Size()
	assert.Equal(t, 64, prefLen)
	assert.Equal(t, 128, totalLen)
}

func TestNewBitmapAllocatorOrderNegative(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8::/56")
	require.NoError(t, err)

	// requested size smaller than the pool it's carved from: allocOrder < 0
	_, err = bitmap.NewBitmapAllocator(*prefix, 48)
	assert.EqualError(t, err, "the size of allocated prefixes cannot be larger than the pool they're allocated from")
}

func TestNewBitmapAllocatorOrderNotRepresentable(t *testing.T) {
	_, prefix, err := net.ParseCIDR("::/0")
	require.NoError(t, err)

	// allocOrder == strconv.IntSize: not representable as a bitset index
	_, err = bitmap.NewBitmapAllocator(*prefix, strconv.IntSize)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not representable")
}

func TestNewBitmapAllocatorLargePoolWarns(t *testing.T) {
	_, prefix, err := net.ParseCIDR("::/0")
	require.NoError(t, err)

	// allocOrder == 32: hits the "large pool" warning but still succeeds, since
	// bitset.Cap() (^uint(0)) is never exceeded while allocOrder < strconv.IntSize
	alloc, err := bitmap.NewBitmapAllocator(*prefix, 32)
	require.NoError(t, err)

	res, err := alloc.Allocate(net.IPNet{})
	require.NoError(t, err)
	prefLen, _ := res.Mask.Size()
	assert.Equal(t, 32, prefLen)
}

func prefixSizeForAllocs(allocs int) int {
	return int(math.Ceil(math.Log2(float64(allocs))))
}

func BenchmarkParallelAllocInitiallyEmpty(b *testing.B) {
	_, prefix, err := net.ParseCIDR("2001:db8::/56")
	if err != nil {
		b.Fatal(err)
	}
	alloc, err := bitmap.NewBitmapAllocator(*prefix, 56+prefixSizeForAllocs(b.N)+2) // Use max 25% of the bitmap (initially empty)
	if err != nil {
		b.Fatal(err)
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if n, err := alloc.Allocate(net.IPNet{}); err != nil {
				b.Logf("Could not allocate (got %v and an error): %v", n, err)
				b.Fail()
			}
		}
	})
}
