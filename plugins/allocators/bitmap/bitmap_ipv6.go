// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

// Same free-address bitmap as IPv4Allocator. An IPv6 address does not fit a
// native integer, so the range is kept as two uint64 halves.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sync"

	"github.com/bits-and-blooms/bitset"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

var (
	errIPv6NotInRange = errors.New("IPv6 address outside of allowed range")
	errInvalidIPv6    = errors.New("invalid IPv6 address passed as input")
)

// One bit per address, so 2^32 caps the bitmap at 512MiB. A /96 is the
// widest pool that fits.
const maxIPv6RangeSize = 1 << 32

// IPv6Allocator allocates single addresses out of a contiguous IPv6 range.
type IPv6Allocator struct {
	startHi, startLo uint64
	size             uint64

	// bitset is not goroutine-safe, hence the mutex.
	bitmap *bitset.BitSet
	l      sync.Mutex
}

// Cannot carry past the top of the address: start+size-1 is the end address,
// validated when the allocator was built.
func (a *IPv6Allocator) toIP(offset uint) net.IP {
	if uint64(offset) >= a.size {
		panic("BUG: offset out of bounds")
	}

	lo, carry := bits.Add64(a.startLo, uint64(offset), 0)
	hi, _ := bits.Add64(a.startHi, 0, carry)

	r := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(r[:8], hi)
	binary.BigEndian.PutUint64(r[8:], lo)
	return r
}

// Unlike the IPv4 sibling, a malformed address and an out-of-range one get
// different errors, so a caller can tell them apart.
func (a *IPv6Allocator) toOffset(ip net.IP) (uint, error) {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return 0, errInvalidIPv6
	}

	hi := binary.BigEndian.Uint64(v6[:8])
	lo := binary.BigEndian.Uint64(v6[8:])

	loOff, borrow := bits.Sub64(lo, a.startLo, 0)
	hiOff, borrow := bits.Sub64(hi, a.startHi, borrow)
	if borrow != 0 || hiOff != 0 || loOff >= a.size {
		return 0, errIPv6NotInRange
	}

	// loOff < size <= 1<<32, which fits a uint on the targeted 64-bit platforms.
	return uint(loOff), nil
}

// Allocate reserves an IPv6 address for a client.
// A bad hint falls back to offset 0, and from there to the first free address.
func (a *IPv6Allocator) Allocate(hint net.IPNet) (n net.IPNet, err error) {
	n.Mask = net.CIDRMask(128, 128)

	// Only a hint: the error is deliberately dropped.
	hintOffset, _ := a.toOffset(hint.IP)

	a.l.Lock()
	defer a.l.Unlock()

	var next uint
	if !a.bitmap.Test(hintOffset) {
		next = hintOffset
	} else {
		avail, ok := a.bitmap.NextClear(0)
		if !ok {
			return n, allocators.ErrNoAddrAvail
		}
		next = avail
	}

	a.bitmap.Set(next)
	n.IP = a.toIP(next)
	return
}

// Free releases the given IPv6 address back to the pool. It passes toOffset's
// error through, where IPv4Allocator.Free flattens it to one message.
func (a *IPv6Allocator) Free(n net.IPNet) error {
	offset, err := a.toOffset(n.IP)
	if err != nil {
		return err
	}

	a.l.Lock()
	defer a.l.Unlock()

	if !a.bitmap.Test(offset) {
		return &allocators.ErrDoubleFree{Loc: n}
	}
	a.bitmap.Clear(offset)
	return nil
}

// Size reports how many addresses the pool holds.
func (a *IPv6Allocator) Size() uint64 {
	return a.size
}

// NewIPv6Allocator creates a new allocator handing out addresses from the
// inclusive range [start, end].
func NewIPv6Allocator(start, end net.IP) (*IPv6Allocator, error) {
	s6, e6 := start.To16(), end.To16()
	if s6 == nil || start.To4() != nil || e6 == nil || end.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 addresses given to create the allocator: [%s,%s]", start, end)
	}

	startHi := binary.BigEndian.Uint64(s6[:8])
	startLo := binary.BigEndian.Uint64(s6[8:])
	endHi := binary.BigEndian.Uint64(e6[:8])
	endLo := binary.BigEndian.Uint64(e6[8:])

	distLo, borrow := bits.Sub64(endLo, startLo, 0)
	distHi, borrow := bits.Sub64(endHi, startHi, borrow)
	if borrow != 0 {
		return nil, errors.New("no IPs in the given range to allocate")
	}
	if distHi != 0 || distLo >= maxIPv6RangeSize {
		return nil, fmt.Errorf("IPv6 range [%s,%s] holds more than %d addresses, the widest supported pool is a /96",
			start, end, uint64(maxIPv6RangeSize))
	}

	size := distLo + 1

	return &IPv6Allocator{
		startHi: startHi,
		startLo: startLo,
		size:    size,
		// size <= 1<<32, which fits a uint on the targeted 64-bit platforms.
		bitmap: bitset.New(uint(size)),
	}, nil
}
