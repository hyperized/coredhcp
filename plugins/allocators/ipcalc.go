// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package allocators

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
)

// ErrOverflow is returned when IP arithmetic carries past bit 0 or bit 128.
var ErrOverflow = errors.New("operation overflows")

// Offset returns the absolute distance between a and b in units of
// /prefixLength subnets, discarding anything finer, and errors past 2^64 units.
// Allocators index their bitmap by this offset from the first IP of the range.
func Offset(a, b net.IP, prefixLength int) (uint64, error) {
	if prefixLength > 128 || prefixLength < 0 {
		return 0, errors.New("prefix out of range")
	}

	reverse := bytes.Compare(a, b)
	if reverse == 0 {
		return 0, nil
	} else if reverse < 0 {
		a, b = b, a
	}

	// Cut [a:b:c:d|e:f:g:h] so the halves are native integers.
	ah, bh := binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(b[:8])

	if prefixLength <= 64 {
		// Only the high half matters, so the distance always fits 64 bits; the
		// shift drops everything right of the cut: [(a:b:c):d] => [0:a:b:c].
		return (ah - bh) >> (64 - uint(prefixLength)), nil
	}

	// General case where both high and low bits matter
	al, bl := binary.BigEndian.Uint64(a[8:]), binary.BigEndian.Uint64(b[8:])
	distanceLow, borrow := bits.Sub64(al, bl, 0)

	distanceHigh, _ := bits.Sub64(ah, bh, borrow) // [a:b:c:d] - [1:2:3:4]

	// The cut falls inside the low half, so [a:b:c:d] - [1:2:3:4] has to reduce
	// to [0:0:0:d-4] or adding it to the low bits overflows.
	if distanceHigh >= (1 << (128 - uint(prefixLength))) {
		return 0, ErrOverflow
	}

	// [a:b:c:(d]
	//          [e:f:g):h]
	// <--------------->   prefixLen
	//                 <-> 128 - prefixLen (cut right)
	// <----->             prefixLen - 64 (cut left)
	distanceHigh <<= uint(prefixLength) - 64
	distanceLow >>= 128 - uint(prefixLength)
	return distanceHigh + distanceLow, nil
}

// AddPrefixes returns the nth /unit subnet after ip, the converse of Offset,
// turning an allocator table index back into a prefix.
func AddPrefixes(ip net.IP, n, unit uint64) (net.IP, error) {
	if unit == 0 && n != 0 {
		return net.IP{}, ErrOverflow
	} else if n == 0 {
		return ip, nil
	}
	if len(ip) != 16 {
		// v4-mapped is fine; the arithmetic just needs 128 bits.
		return net.IP{}, errors.New("AddPrefixes needs 128-bit IPs")
	}

	// Go has no 128-bit integer, so this runs as a uint64 pair.
	iph, ipl := binary.BigEndian.Uint64(ip[:8]), binary.BigEndian.Uint64(ip[8:])

	var offh, offl uint64
	if unit <= 64 {
		offh = n << (64 - unit)
	} else {
		offh, offl = bits.Mul64(n, 1<<(128-unit))
	}

	ipl, carry := bits.Add64(offl, ipl, 0)
	iph, carry = bits.Add64(offh, iph, carry)
	if carry != 0 {
		return net.IP{}, ErrOverflow
	}

	ret := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ret[:8], iph)
	binary.BigEndian.PutUint64(ret[8:], ipl)

	return ret, nil
}
