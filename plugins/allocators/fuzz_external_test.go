// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package allocators_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

// to16 pads/truncates to 16 bytes, the length Offset/AddPrefixes assume for a 128-bit address.
func to16(b []byte) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, b)
	return ip
}

// FuzzOffset checks that Offset is symmetric: swapping a and b must give the
// same value and error-ness, regardless of the underlying arithmetic.
func FuzzOffset(f *testing.F) {
	a := net.ParseIP("2001:db8:0:aabb::").To16()
	b := net.ParseIP("2001:db8:ff::34").To16()
	for _, p := range []int{0, 16, 32, 48, 64, 73, 80, 96, 112, 128} {
		f.Add([]byte(a), []byte(b), p)
	}
	f.Add([]byte(a), []byte(a), 64) // identical addresses
	f.Add(make([]byte, 16), make([]byte, 16), 0)
	f.Add(bytes.Repeat([]byte{0xff}, 16), make([]byte, 16), 128)
	f.Add([]byte{1, 2, 3}, []byte{4, 5}, 200) // hostile: short slices, out-of-range prefix
	f.Add(make([]byte, 16), make([]byte, 16), -1)
	f.Add(make([]byte, 16), make([]byte, 16), 129)

	f.Fuzz(func(t *testing.T, aBytes, bBytes []byte, prefixLength int) {
		ipA, ipB := to16(aBytes), to16(bBytes)

		var off1, off2 uint64
		var err1, err2 error
		assert.NotPanics(t, func() {
			off1, err1 = allocators.Offset(ipA, ipB, prefixLength)
		})
		assert.NotPanics(t, func() {
			off2, err2 = allocators.Offset(ipB, ipA, prefixLength)
		})

		if err1 != nil || err2 != nil {
			assert.Equal(t, err1 != nil, err2 != nil, "Offset(a,b,p) and Offset(b,a,p) must fail/succeed together")
			return
		}
		assert.Equal(t, off1, off2, "Offset must be symmetric: same absolute distance regardless of argument order")
	})
}

// FuzzAddPrefixes checks AddPrefixes never panics on arbitrary input, and
// that growing a base by n /unit prefixes round-trips through Offset to n.
func FuzzAddPrefixes(f *testing.F) {
	base := net.ParseIP("2001:db8::").To16()
	f.Add([]byte(base), uint64(0xff), uint64(64))
	f.Add([]byte(base), uint64(0x1), uint64(128))
	f.Add([]byte(base), uint64(0xff), uint64(32))
	f.Add([]byte(base), uint64(0x1), uint64(16))
	f.Add([]byte(base), uint64(0xff), uint64(65))
	f.Add([]byte(base), uint64(0xff), uint64(8))                 // overflow case
	f.Add([]byte{10, 0, 0, 1}, uint64(64), uint64(32))           // hostile: 4-byte IP
	f.Add(make([]byte, 16), uint64(0), uint64(0))                // n==0 short circuit
	f.Add(make([]byte, 16), ^uint64(0), ^uint64(0))              // hostile: max n, max unit
	f.Add(bytes.Repeat([]byte{0xff}, 16), ^uint64(0), uint64(1)) // hostile: near top of address space

	f.Fuzz(func(t *testing.T, ipBytes []byte, n, unitRaw uint64) {
		// Only checked for panics: an out-of-range unit or a non-16-byte ip has
		// no defined round-trip meaning.
		assert.NotPanics(t, func() {
			_, _ = allocators.AddPrefixes(net.IP(ipBytes), n, unitRaw)
		})

		if len(ipBytes) != 16 {
			return
		}
		base := to16(ipBytes)

		// Clamp so n fits unit's bits: past that, AddPrefixes' left shift silently
		// drops n's high bits before its own overflow check can see them.
		unit := unitRaw % 129
		nn := n
		switch {
		case unit == 0:
			nn = 0
		case unit < 64:
			nn = n & (uint64(1)<<unit - 1)
		}

		grown, err := allocators.AddPrefixes(base, nn, unit)
		if err != nil {
			return // legitimate overflow (grown past the top of the address space)
		}
		require.Len(t, grown, 16)

		off, err := allocators.Offset(grown, base, int(unit))
		require.NoError(t, err, "Offset must recover a distance AddPrefixes just added: base=%v n=%d unit=%d grown=%v", base, nn, unit, grown)
		assert.Equal(t, nn, off, "AddPrefixes then Offset must round-trip to the same n")
	})
}
