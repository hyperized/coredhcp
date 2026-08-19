// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package allocators_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
)

func TestErrDoubleFreeError(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	dfErr := &allocators.ErrDoubleFree{Loc: *prefix}
	assert.Equal(t, "Attempted to free unallocated block at "+prefix.String(), dfErr.Error())
}

func TestErrNoAddrAvailMessage(t *testing.T) {
	assert.EqualError(t, allocators.ErrNoAddrAvail, "no address available to allocate")
}
