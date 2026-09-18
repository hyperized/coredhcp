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
	assert.Contains(t, dfErr.Error(), "attempted to free the unallocated block at "+prefix.String())
}

func TestErrNoAddrAvailMessage(t *testing.T) {
	assert.ErrorContains(t, allocators.ErrNoAddrAvail, "no address available to allocate")
}
