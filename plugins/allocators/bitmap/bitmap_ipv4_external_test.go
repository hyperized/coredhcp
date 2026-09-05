// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

func getv4Allocator(t *testing.T) *bitmap.IPv4Allocator {
	t.Helper()
	alloc, err := bitmap.NewIPv4Allocator(net.IPv4(192, 0, 2, 0), net.IPv4(192, 0, 2, 255))
	require.NoError(t, err)

	return alloc
}

func TestIPv4AllocateAndDoubleFree(t *testing.T) {
	alloc := getv4Allocator(t)

	n1, err := alloc.Allocate(net.IPNet{})
	require.NoError(t, err)

	n2, err := alloc.Allocate(net.IPNet{})
	require.NoError(t, err)

	assert.False(t, n1.IP.Equal(n2.IP), "that address was already allocated")

	require.NoError(t, alloc.Free(n1))

	err = alloc.Free(n1)
	require.Error(t, err, "expected DoubleFree error")
	var dfErr *allocators.ErrDoubleFree
	assert.ErrorAs(t, err, &dfErr)
}

func TestIPv4AllocateWithHintOutsidePool(t *testing.T) {
	alloc := getv4Allocator(t)

	hint := net.IPv4(198, 51, 100, 5)
	res, err := alloc.Allocate(net.IPNet{IP: hint, Mask: net.CIDRMask(32, 32)})
	require.NoError(t, err, "failed to allocate with invalid hint")

	_, prefix, err := net.ParseCIDR("192.0.2.0/24")
	require.NoError(t, err)
	assert.True(t, prefix.Contains(res.IP), "obtained prefix outside of range: %v", res)

	prefLen, totalLen := res.Mask.Size()
	assert.Equal(t, 32, prefLen)
	assert.Equal(t, 32, totalLen)
}

func TestIPv4AllocateExhaustion(t *testing.T) {
	// A single-address pool: the first Allocate hits the hint-defaulted fast
	// path; the second falls through to NextClear and finds nothing.
	alloc, err := bitmap.NewIPv4Allocator(net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 1))
	require.NoError(t, err)

	_, err = alloc.Allocate(net.IPNet{})
	require.NoError(t, err)

	_, err = alloc.Allocate(net.IPNet{})
	assert.ErrorIs(t, err, allocators.ErrNoAddrAvail)
}

func TestIPv4FreeOutOfRange(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
	}{
		{"valid v4 address outside the pool", net.IPv4(198, 51, 100, 5)},
		{"non-v4 address", net.ParseIP("2001:db8::1")},
	}

	alloc := getv4Allocator(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alloc.Free(net.IPNet{IP: tt.ip, Mask: net.CIDRMask(32, 32)})
			// Free always reports the same "out of range" error, even when the
			// underlying cause was actually an invalid (non-v4) address.
			assert.EqualError(t, err, "IPv4 address outside of allowed range")
		})
	}
}

func TestNewIPv4AllocatorInvalidAddresses(t *testing.T) {
	tests := []struct {
		name       string
		start, end net.IP
	}{
		{"invalid start", net.ParseIP("2001:db8::1"), net.IPv4(192, 0, 2, 255)},
		{"invalid end", net.IPv4(192, 0, 2, 0), net.ParseIP("2001:db8::1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bitmap.NewIPv4Allocator(tt.start, tt.end)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid IPv4 addresses given to create the allocator")
		})
	}
}

func TestNewIPv4AllocatorStartAfterEnd(t *testing.T) {
	_, err := bitmap.NewIPv4Allocator(net.IPv4(192, 0, 2, 255), net.IPv4(192, 0, 2, 0))
	assert.EqualError(t, err, "no IPs in the given range to allocate")
}
