// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package allocators provides the interface and the algorithms for allocating
// prefixes of various sizes within a larger prefix.
package allocators

import (
	"errors"
	"fmt"
	"net"
)

// Allocator finds and reserves blocks. Expiry is out of scope: garbage
// collection has to be handled separately.
type Allocator interface {
	// Allocate returns a prefix, honouring hint's size and location where it
	// can. A successful allocation is never an error, hint or no hint.
	Allocate(hint net.IPNet) (net.IPNet, error)

	// Free returns the prefix containing the given network to the pool, and
	// may report ErrDoubleFree for a prefix that was never allocated.
	Free(net.IPNet) error
}

// ErrDoubleFree is reported by Allocator.Free for a non-allocated block.
type ErrDoubleFree struct {
	Loc net.IPNet
}

// Error names the block that was freed without being allocated.
func (err *ErrDoubleFree) Error() string {
	return fmt.Sprint("Attempted to free unallocated block at ", err.Loc.String())
}

// ErrNoAddrAvail is returned when no unallocated space is left.
var ErrNoAddrAvail = errors.New("no address available to allocate")
