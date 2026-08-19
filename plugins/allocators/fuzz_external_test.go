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

// to16 pads/truncates arbitrary fuzz-provided bytes to exactly 16, the
// length Offset/AddPrefixes treat as a 128-bit address (see ipcalc.go's
// a[:8]/a[8:] slicing, which assumes 16 bytes).
func to16(b []byte) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, b)
	return ip
}

// FuzzOffset fuzzes Offset with arbitrary 16-byte IPs and an arbitrary
// prefix length. Offset's own doc comment says it "returns the absolute
// distance between addresses a and b", and the implementation enforces that
// by comparing a and b and always subtracting the smaller from the larger -
// so, regardless of which was fuzzed into which argument position, swapping
// the two arguments must yield exactly the same result (same value, same
// error-ness). That symmetry holds independent of the (fragile, borrow- and
// shift-sensitive) arithmetic used to actually compute the distance, so it
// is a safe invariant to fuzz without reimplementing that arithmetic here.
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

// FuzzAddPrefixes fuzzes AddPrefixes with an arbitrary IP and arbitrary
// uint64s, first against the raw arbitrary inputs (checking only for
// panics, since a hostile unit or n has no obligation to make arithmetic
// sense), then against inputs clamped into AddPrefixes' documented domain
// (a 128-bit ip, unit in [0,128], n representable within that unit) to check
// the round trip against Offset: growing a base by n /unit prefixes and then
// measuring the Offset back to that same base must recover n exactly.
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
		// Raw, unclamped call: only "does not panic" is asserted, since a
		// unit outside [0,128] or an ip that isn't 16 bytes has no defined
		// round-trip meaning (AddPrefixes' own len(ip)!=16 check is what
		// makes this safe; see NewIPv4Allocator/bitmap.Allocator's actual
		// callers, which never pass anything else).
		assert.NotPanics(t, func() {
			_, _ = allocators.AddPrefixes(net.IP(ipBytes), n, unitRaw)
		})

		if len(ipBytes) != 16 {
			return
		}
		base := to16(ipBytes)

		// Clamp into AddPrefixes' documented domain: unit is a prefix
		// length (0-128), and n must fit within that many bits or the left
		// shift `n << (64-unit)` used for unit<=64 silently drops n's high
		// bits before the overflow check ever sees them - that's a
		// separate, already-latent property of AddPrefixes unrelated to
		// what this test is trying to establish (the round trip through
		// Offset), so inputs are shaped to avoid it rather than assert
		// through it.
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
