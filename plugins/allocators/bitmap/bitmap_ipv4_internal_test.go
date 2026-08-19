// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bitmap

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToIPPanicsOnOutOfBoundsOffset(t *testing.T) {
	alloc, err := NewIPv4Allocator(net.IPv4(192, 0, 2, 0), net.IPv4(192, 0, 2, 255))
	require.NoError(t, err)

	defer func() {
		r := recover()
		require.NotNil(t, r, "expected toIP to panic on an out-of-bounds offset")
		assert.Equal(t, "BUG: offset out of bounds", r)
	}()

	alloc.toIP(uint(alloc.end-alloc.start) + 1)
	t.Fatal("toIP should have panicked before reaching this point")
}

func TestToOffsetSentinelErrors(t *testing.T) {
	alloc, err := NewIPv4Allocator(net.IPv4(192, 0, 2, 0), net.IPv4(192, 0, 2, 255))
	require.NoError(t, err)

	_, err = alloc.toOffset(net.ParseIP("2001:db8::1"))
	assert.ErrorIs(t, err, errInvalidIP)

	_, err = alloc.toOffset(net.IPv4(198, 51, 100, 5))
	assert.ErrorIs(t, err, errNotInRange)

	off, err := alloc.toOffset(net.IPv4(192, 0, 2, 0))
	require.NoError(t, err)
	assert.Equal(t, uint(0), off)
}
