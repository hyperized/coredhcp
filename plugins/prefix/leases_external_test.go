// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/plugins/prefix"
)

// Unregisters in Cleanup because the source registry is global and would
// otherwise leak this instance into later tests.
func registeredSource(t *testing.T, name string) leases.Source {
	t.Helper()
	for _, s := range leases.Sources() {
		if s.Name() == name {
			t.Cleanup(func() { leases.Unregister(s) })
			return s
		}
	}
	t.Fatalf("no source registered as %q", name)
	return nil
}

func TestLeasesFollowTheHandler(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8:9::/60", "64")
	require.NoError(t, err)
	src := registeredSource(t, "prefix 2001:db8:9::/60")

	assert.Empty(t, src.Leases())
	assert.Equal(t, []leases.Pool{{
		Source: "prefix 2001:db8:9::/60",
		Family: 6,
		Range:  "2001:db8:9::/60",
		Size:   16,
	}}, src.Pools())

	duid := testDUID()
	solicitWith(t, h, duid)

	held := src.Leases()
	require.Len(t, held, 1)
	assert.Equal(t, uint8(6), held[0].Family)
	assert.Equal(t, hex.EncodeToString(duid.ToBytes()), held[0].Client)
	assert.Equal(t, 64, held[0].Address.Bits())
	assert.True(t, held[0].Address.Addr().Is6())
	assert.False(t, held[0].Static)
	assert.False(t, held[0].Expires.IsZero())
	assert.Equal(t, "prefix 2001:db8:9::/60", held[0].Source)

	pool := src.Pools()[0]
	assert.Equal(t, 1, pool.Used)
	assert.Equal(t, 0, pool.Quarantined)
}

func TestLeasesCountPrefixesPerClient(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8:10::/60", "64")
	require.NoError(t, err)
	src := registeredSource(t, "prefix 2001:db8:10::/60")

	// Well inside the per-client maximum, so each IA_PD gets its own lease.
	solicitManyIAPDs(t, h, testDUID(), 3)

	assert.Len(t, src.Leases(), 3)
	assert.Equal(t, 3, src.Pools()[0].Used)
}
