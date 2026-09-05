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

func getv6Allocator(t *testing.T) *bitmap.IPv6Allocator {
	t.Helper()
	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::ff"))
	require.NoError(t, err)

	return alloc
}

func TestIPv6AllocateAndDoubleFree(t *testing.T) {
	alloc := getv6Allocator(t)

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

func TestIPv6AllocateWithHintOutsidePool(t *testing.T) {
	alloc := getv6Allocator(t)

	hint := net.ParseIP("2001:db9::5")
	res, err := alloc.Allocate(net.IPNet{IP: hint, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err, "failed to allocate with invalid hint")

	_, prefix, err := net.ParseCIDR("2001:db8::/120")
	require.NoError(t, err)
	assert.True(t, prefix.Contains(res.IP), "obtained address outside of range: %v", res)

	prefLen, totalLen := res.Mask.Size()
	assert.Equal(t, 128, prefLen)
	assert.Equal(t, 128, totalLen)
}

func TestIPv6AllocateWithHintHonoured(t *testing.T) {
	alloc := getv6Allocator(t)

	hint := net.ParseIP("2001:db8::42")
	res, err := alloc.Allocate(net.IPNet{IP: hint, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err)
	assert.True(t, hint.Equal(res.IP))
}

func TestIPv6AllocateWithHintAlreadyTaken(t *testing.T) {
	alloc := getv6Allocator(t)

	hint := net.ParseIP("2001:db8::42")
	first, err := alloc.Allocate(net.IPNet{IP: hint, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err)
	require.True(t, hint.Equal(first.IP))

	second, err := alloc.Allocate(net.IPNet{IP: hint, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err)
	assert.False(t, hint.Equal(second.IP), "hint was already taken, expected a different address")
}

func TestIPv6AllocateExhaustion(t *testing.T) {
	// A single-address pool: the first Allocate hits the hint-defaulted fast
	// path; the second falls through to NextClear and finds nothing.
	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"))
	require.NoError(t, err)

	_, err = alloc.Allocate(net.IPNet{})
	require.NoError(t, err)

	_, err = alloc.Allocate(net.IPNet{})
	assert.ErrorIs(t, err, allocators.ErrNoAddrAvail)
}

func TestIPv6BoundaryAddresses(t *testing.T) {
	start := net.ParseIP("2001:db8::10")
	end := net.ParseIP("2001:db8::20")
	alloc, err := bitmap.NewIPv6Allocator(start, end)
	require.NoError(t, err)

	firstNet := net.IPNet{IP: start, Mask: net.CIDRMask(128, 128)}
	res, err := alloc.Allocate(firstNet)
	require.NoError(t, err)
	assert.True(t, start.Equal(res.IP))
	require.NoError(t, alloc.Free(firstNet))

	lastNet := net.IPNet{IP: end, Mask: net.CIDRMask(128, 128)}
	res, err = alloc.Allocate(lastNet)
	require.NoError(t, err)
	assert.True(t, end.Equal(res.IP))
	require.NoError(t, alloc.Free(lastNet))

	belowStart := net.IPNet{IP: net.ParseIP("2001:db8::f"), Mask: net.CIDRMask(128, 128)}
	err = alloc.Free(belowStart)
	assert.EqualError(t, err, "IPv6 address outside of allowed range")

	aboveEnd := net.IPNet{IP: net.ParseIP("2001:db8::21"), Mask: net.CIDRMask(128, 128)}
	err = alloc.Free(aboveEnd)
	assert.EqualError(t, err, "IPv6 address outside of allowed range")
}

func TestIPv6AllocateAcrossWordBoundary(t *testing.T) {
	// this range straddles the 64-bit split between the stored hi and lo
	// halves, which is what exercises the carry handling in toIP/toOffset
	start := net.ParseIP("2001:db8::ffff:ffff:ffff:ffff")
	end := net.ParseIP("2001:db8:0:1::10")
	alloc, err := bitmap.NewIPv6Allocator(start, end)
	require.NoError(t, err)
	assert.Equal(t, uint64(18), alloc.Size())

	// the address right after the rollover: allocating it by hint only
	// lands correctly if the carry into the hi half was computed right
	rollover := net.ParseIP("2001:db8:0:1::")
	res, err := alloc.Allocate(net.IPNet{IP: rollover, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err)
	assert.True(t, rollover.Equal(res.IP))

	last, err := alloc.Allocate(net.IPNet{IP: end, Mask: net.CIDRMask(128, 128)})
	require.NoError(t, err)
	assert.True(t, end.Equal(last.IP))
}

func TestIPv6FreeInvalidAddress(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
	}{
		{"IPv4 address", net.IPv4(192, 0, 2, 1)},
		{"nil IP", nil},
	}

	alloc := getv6Allocator(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alloc.Free(net.IPNet{IP: tt.ip, Mask: net.CIDRMask(128, 128)})
			assert.EqualError(t, err, "invalid IPv6 address passed as input")
		})
	}
}

func TestIPv6Size(t *testing.T) {
	tests := []struct {
		name       string
		start, end net.IP
		want       uint64
	}{
		{"single address", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), 1},
		{"a /120", net.ParseIP("2001:db8::100"), net.ParseIP("2001:db8::1ff"), 256},
		{"widest allowed pool, built from a /96 pair", net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::ffff:ffff"), 1 << 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc, err := bitmap.NewIPv6Allocator(tt.start, tt.end)
			require.NoError(t, err)
			assert.Equal(t, tt.want, alloc.Size())
		})
	}
}

func TestNewIPv6AllocatorInvalidAddresses(t *testing.T) {
	tests := []struct {
		name       string
		start, end net.IP
	}{
		{"invalid start", net.IP{1, 2, 3}, net.ParseIP("2001:db8::ff")},
		{"invalid end", net.ParseIP("2001:db8::"), net.IP{1, 2, 3}},
		{"IPv4 start", net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::ff")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bitmap.NewIPv6Allocator(tt.start, tt.end)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid IPv6 addresses given to create the allocator")
		})
	}
}

func TestNewIPv6AllocatorStartAfterEnd(t *testing.T) {
	_, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8::ff"), net.ParseIP("2001:db8::"))
	assert.EqualError(t, err, "no IPs in the given range to allocate")
}

func TestNewIPv6AllocatorRangeTooWide(t *testing.T) {
	tests := []struct {
		name       string
		start, end net.IP
	}{
		{"high half non-zero", net.ParseIP("2001:db8::"), net.ParseIP("2001:db9::")},
		{"low half too big", net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::1:0:0:0")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bitmap.NewIPv6Allocator(tt.start, tt.end)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "widest supported pool is a /96")
		})
	}
}
