// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

// FuzzIPv4AllocatorOps interprets each fuzzed byte as one operation against
// an IPv4Allocator over a small (16-address) range: the top bit selects
// Allocate (with the remaining 7 bits as an in-range hint) or Free (with the
// remaining 7 bits picking, modulo the range size, which offset to free),
// keeping the op stream dense enough to reliably hit both allocation and
// double-free paths within a short fuzz run. It tracks which offsets are
// currently held to check the allocator's own invariants: Allocate never
// returns an address outside [start,end] or one already held, Free of a
// held address succeeds and releases it, and Free of a non-held address
// reports a double free rather than corrupting state.
func FuzzIPv4AllocatorOps(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x80, 0x00}) // allocate, allocate, free(offset 0), allocate
	f.Add([]byte{})
	f.Add([]byte{0x80}) // free with nothing allocated yet: must double-free-error, not panic
	allocateAll := make([]byte, 20)
	for i := range allocateAll {
		allocateAll[i] = byte(i) // allocate until exhaustion, then keep trying
	}
	f.Add(allocateAll)
	freeStorm := make([]byte, 20)
	for i := range freeStorm {
		freeStorm[i] = 0x80 | byte(i) // repeated frees of different/overlapping offsets
	}
	f.Add(freeStorm)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x7f, 0x7f, 0x7f, 0x7f})

	f.Fuzz(func(t *testing.T, ops []byte) {
		alloc, err := NewIPv4Allocator(net.IPv4(192, 0, 2, 0), net.IPv4(192, 0, 2, 15))
		if err != nil {
			t.Fatalf("NewIPv4Allocator: %v", err)
		}
		rangeSize := alloc.end - alloc.start + 1

		held := make(map[uint32]bool)
		toIPNet := func(offset uint32) net.IPNet {
			ip := make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, alloc.start+offset)
			return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		for _, b := range ops {
			offset := uint32(b&0x7f) % rangeSize
			if b&0x80 != 0 {
				wasHeld := held[offset]
				err := alloc.Free(toIPNet(offset))
				if wasHeld {
					if err != nil {
						t.Fatalf("Free of held offset %d failed: %v", offset, err)
					}
					delete(held, offset)
				} else if err == nil {
					t.Fatalf("Free of non-held offset %d succeeded, want a double-free error", offset)
				}
				continue
			}

			n, err := alloc.Allocate(toIPNet(offset))
			if err != nil {
				if err != allocators.ErrNoAddrAvail { //nolint:errorlint // sentinel returned verbatim by Allocate
					t.Fatalf("Allocate returned unexpected error: %v", err)
				}
				continue
			}

			gotOffset, oerr := alloc.toOffset(n.IP)
			if oerr != nil {
				t.Fatalf("Allocate returned an address rejected by toOffset: %v (%v)", n.IP, oerr)
			}
			if uint32(gotOffset) >= rangeSize {
				t.Fatalf("Allocate returned offset %d outside [0,%d)", gotOffset, rangeSize)
			}
			if held[uint32(gotOffset)] {
				t.Fatalf("Allocate returned already-held offset %d", gotOffset)
			}
			held[uint32(gotOffset)] = true
		}
	})
}
