// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

import (
	"net"
	"testing"
)

// BenchmarkIPv4AllocatorAllocateMiss allocates over a large, mostly-empty
// range with an empty hint, which never matches a free address and forces
// the bitmap search on every call.
func BenchmarkIPv4AllocatorAllocateMiss(b *testing.B) {
	b.ReportAllocs()

	alloc, err := NewIPv4Allocator(net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255))
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if _, err := alloc.Allocate(net.IPNet{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIPv4AllocatorAllocateHintHit mimics a client renewing the same
// lease over and over: the address is freed and immediately reallocated
// with a hint that matches it, taking the direct-hit path every time.
func BenchmarkIPv4AllocatorAllocateHintHit(b *testing.B) {
	b.ReportAllocs()

	alloc, err := NewIPv4Allocator(net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 255))
	if err != nil {
		b.Fatal(err)
	}
	hint := net.IPNet{IP: net.IPv4(10, 0, 0, 5).To4(), Mask: net.CIDRMask(32, 32)}
	if _, err := alloc.Allocate(hint); err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if err := alloc.Free(hint); err != nil {
			b.Fatal(err)
		}
		if _, err := alloc.Allocate(hint); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIPv4AllocatorFree measures Free in isolation: each iteration
// allocates an address outside the timer, then frees it under the timer.
func BenchmarkIPv4AllocatorFree(b *testing.B) {
	b.ReportAllocs()

	alloc, err := NewIPv4Allocator(net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 255))
	if err != nil {
		b.Fatal(err)
	}
	hint := net.IPNet{IP: net.IPv4(10, 0, 0, 5).To4(), Mask: net.CIDRMask(32, 32)}

	for b.Loop() {
		b.StopTimer()
		n, err := alloc.Allocate(hint)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if err := alloc.Free(n); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPrefixAllocatorAllocate exercises the IPv6 prefix allocator's
// search path over a large pool with an empty hint, reusing the getAllocator
// helper from bitmap_internal_test.go.
func BenchmarkPrefixAllocatorAllocate(b *testing.B) {
	b.ReportAllocs()

	alloc := getAllocator(b, 24)

	for b.Loop() {
		if _, err := alloc.Allocate(net.IPNet{}); err != nil {
			b.Fatal(err)
		}
	}
}
