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

func TestIPv6ToIPPanicsOnOutOfBoundsOffset(t *testing.T) {
	alloc, err := NewIPv6Allocator(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::ff"))
	require.NoError(t, err)

	defer func() {
		r := recover()
		require.NotNil(t, r, "expected toIP to panic on an out-of-bounds offset")
		assert.Equal(t, "BUG: offset out of bounds", r)
	}()

	alloc.toIP(uint(alloc.size))
	t.Fatal("toIP should have panicked before reaching this point")
}

func TestIPv6ToOffsetSentinelErrors(t *testing.T) {
	alloc, err := NewIPv6Allocator(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::ff"))
	require.NoError(t, err)

	_, err = alloc.toOffset(net.IPv4(192, 0, 2, 1))
	assert.ErrorIs(t, err, errInvalidIPv6)

	_, err = alloc.toOffset(net.ParseIP("2001:db8::1:0"))
	assert.ErrorIs(t, err, errIPv6NotInRange)

	off, err := alloc.toOffset(net.ParseIP("2001:db8::10"))
	require.NoError(t, err)
	assert.Equal(t, uint(0x10), off)
}
