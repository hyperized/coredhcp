// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

// Same logic as the base bitmap, simpler because an IPv4 address is a uint32.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/bits-and-blooms/bitset"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

var (
	errNotInRange = errors.New("IPv4 address outside of allowed range")
	errInvalidIP  = errors.New("invalid IPv4 address passed as input")
)

// IPv4Allocator allocates IPv4 addresses, tracking use with a bitmap.
type IPv4Allocator struct {
	start uint32
	end   uint32

	// bitset is not goroutine-safe, hence the mutex.
	bitmap *bitset.BitSet
	l      sync.Mutex
}

func (a *IPv4Allocator) toIP(offset uint) net.IP {
	if offset > uint(a.end-a.start) {
		panic("BUG: offset out of bounds")
	}

	r := make(net.IP, net.IPv4len)
	// Bounds-checked against end-start just above.
	binary.BigEndian.PutUint32(r, a.start+uint32(offset)) //nolint:gosec // see above
	return r
}

func (a *IPv4Allocator) toOffset(ip net.IP) (uint, error) {
	if ip.To4() == nil {
		return 0, errInvalidIP
	}

	intIP := binary.BigEndian.Uint32(ip.To4())
	if intIP < a.start || intIP > a.end {
		return 0, errNotInRange
	}

	return uint(intIP - a.start), nil
}

// Allocate reserves an IP for a client.
func (a *IPv4Allocator) Allocate(hint net.IPNet) (n net.IPNet, err error) {
	n.Mask = net.CIDRMask(32, 32)

	// Only a hint: a bad one falls back to offset 0.
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

// Free releases the given IP.
func (a *IPv4Allocator) Free(n net.IPNet) error {
	offset, err := a.toOffset(n.IP)
	if err != nil {
		return errNotInRange
	}

	a.l.Lock()
	defer a.l.Unlock()

	if !a.bitmap.Test(offset) {
		return &allocators.ErrDoubleFree{Loc: n}
	}
	a.bitmap.Clear(offset)
	return nil
}

// NewIPv4Allocator creates an allocator over the inclusive range [start, end].
func NewIPv4Allocator(start, end net.IP) (*IPv4Allocator, error) {
	if start.To4() == nil || end.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 addresses given to create the allocator: [%s,%s]", start, end)
	}

	alloc := IPv4Allocator{
		start: binary.BigEndian.Uint32(start.To4()),
		end:   binary.BigEndian.Uint32(end.To4()),
	}

	if alloc.start > alloc.end {
		return nil, errors.New("no IPs in the given range to allocate")
	}
	alloc.bitmap = bitset.New(uint(alloc.end - alloc.start + 1))

	return &alloc, nil
}
