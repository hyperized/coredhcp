// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package allocators_test

import (
	"fmt"
	"net"
	"testing"

	"math/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

func ExampleOffset() {
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 0))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 16))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 32))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 48))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 64))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 73))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 80))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 96))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 112))
	fmt.Println(allocators.Offset(net.ParseIP("2001:db8:0:aabb::"), net.ParseIP("2001:db8:ff::34"), 128))
	// Output:
	// 0 <nil>
	// 0 <nil>
	// 0 <nil>
	// 254 <nil>
	// 16667973 <nil>
	// 8534002176 <nil>
	// 1092352278528 <nil>
	// 71588398925611008 <nil>
	// 0 operation overflows
	// 0 operation overflows
}

func ExampleAddPrefixes() {
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0xff, 64))
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0x1, 128))
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0xff, 32))
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0x1, 16))
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0xff, 65))
	fmt.Println(allocators.AddPrefixes(net.ParseIP("2001:db8::"), 0xff, 8))
	fmt.Println(allocators.AddPrefixes(net.IP{10, 0, 0, 1}, 64, 32))
	// Output:
	// 2001:db8:0:ff:: <nil>
	// 2001:db8::1 <nil>
	// 2001:eb7:: <nil>
	// 2002:db8:: <nil>
	// 2001:db8:0:7f:8000:: <nil>
	// <nil> operation overflows
	// <nil> AddPrefixes needs 128-bit IPs
}

// Offset is used as a hash function, so it needs to be reasonably fast
func BenchmarkOffset(b *testing.B) {
	// Need predictable randomness for benchmark reproducibility
	rng := rand.New(rand.NewSource(0))
	addresses := make([]byte, b.N*net.IPv6len*2)
	_, err := rng.Read(addresses)
	if err != nil {
		b.Fatalf("Could not generate random addresses: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Pre-generated so the loop measures Offset itself, not cache misses.
		_, _ = allocators.Offset(
			addresses[i*2*net.IPv6len:(i*2+1)*net.IPv6len],
			addresses[(i*2+1)*net.IPv6len:(i+1)*2*net.IPv6len],
			(i*4)%128,
		)
	}
}

func TestOffsetIdenticalAddressesReturnsZero(t *testing.T) {
	// bytes.Compare(a, b) == 0 short-circuits before any of the subtraction logic
	ip := net.ParseIP("2001:db8::1")
	got, err := allocators.Offset(ip, ip, 64)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), got)
}

func TestOffsetPrefixOutOfRange(t *testing.T) {
	tests := []struct {
		name         string
		prefixLength int
	}{
		{"negative", -1},
		{"above 128", 129},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := allocators.Offset(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), tt.prefixLength)
			assert.EqualError(t, err, "prefix out of range")
		})
	}
}

func TestAddPrefixesZeroUnitWithNonZeroN(t *testing.T) {
	_, err := allocators.AddPrefixes(net.ParseIP("2001:db8::"), 5, 0)
	assert.ErrorIs(t, err, allocators.ErrOverflow)
}

func TestAddPrefixesZeroNReturnsBaseUnchanged(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	got, err := allocators.AddPrefixes(ip, 0, 64)
	require.NoError(t, err)
	assert.True(t, ip.Equal(got))
}
