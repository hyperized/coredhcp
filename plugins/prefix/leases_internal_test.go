// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
)

// duidKey is the map key the plugin uses: a DUID's wire form held in a string.
// It is not text, which is why Leases hands it out as hex.
var duidKey = string([]byte{0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})

const duidHex = "00030001aabbccddeeff"

// stateWithLeases builds an instance holding the given delegations, without an
// allocator or a sweeper: Leases and Pools read the map and nothing else.
func stateWithLeases(records map[string][]lease) *pluginState {
	return &pluginState{
		name:       "prefix 2001:db8::/48",
		poolRange:  "2001:db8::/48",
		poolBlocks: 1 << 16,
		Records:    records,
	}
}

// mustIPNet parses a CIDR into the net.IPNet shape the allocator produces.
func mustIPNet(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	return *n
}

func TestName(t *testing.T) {
	assert.Equal(t, "prefix 2001:db8::/48", stateWithLeases(nil).Name())
}

func TestLeases(t *testing.T) {
	expired := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	live := time.Date(2026, 9, 5, 14, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		records map[string][]lease
		want    []leases.Lease
	}{
		{
			name:    "no delegations",
			records: map[string][]lease{},
			want:    []leases.Lease{},
		},
		{
			name: "one client holding two prefixes, one of them lapsed",
			records: map[string][]lease{
				duidKey: {
					{Prefix: mustIPNet(t, "2001:db8:0:1::/64"), Expire: live},
					// Lapsed but not swept yet: reported all the same, with
					// the expiry that has already passed.
					{Prefix: mustIPNet(t, "2001:db8:0:2::/64"), Expire: expired},
				},
			},
			want: []leases.Lease{
				{
					Family:  6,
					Client:  duidHex,
					Address: netip.MustParsePrefix("2001:db8:0:1::/64"),
					Expires: live,
					Source:  "prefix 2001:db8::/48",
				},
				{
					Family:  6,
					Client:  duidHex,
					Address: netip.MustParsePrefix("2001:db8:0:2::/64"),
					Expires: expired,
					Source:  "prefix 2001:db8::/48",
				},
			},
		},
		{
			name: "a lease whose prefix is not an address is skipped",
			records: map[string][]lease{
				duidKey: {{Prefix: net.IPNet{IP: net.IP{1, 2, 3}}, Expire: live}},
			},
			want: []leases.Lease{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stateWithLeases(tc.records).Leases()
			slices.SortFunc(got, func(a, b leases.Lease) int {
				return a.Address.Addr().Compare(b.Address.Addr())
			})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLeasesIsASnapshot(t *testing.T) {
	p := stateWithLeases(map[string][]lease{
		duidKey: {{Prefix: mustIPNet(t, "2001:db8:0:1::/64"), Expire: time.Now()}},
	})

	got := p.Leases()
	require.Len(t, got, 1)
	got[0].Client = "scribbled on"

	again := p.Leases()
	require.Len(t, again, 1)
	assert.Equal(t, duidHex, again[0].Client)
}

func TestPools(t *testing.T) {
	p := stateWithLeases(map[string][]lease{
		duidKey: {
			{Prefix: mustIPNet(t, "2001:db8:0:1::/64")},
			{Prefix: mustIPNet(t, "2001:db8:0:2::/64")},
		},
		"other": {{Prefix: mustIPNet(t, "2001:db8:0:3::/64")}},
	})

	// Used counts prefixes, not clients: three delegations across two DUIDs.
	assert.Equal(t, []leases.Pool{{
		Source: "prefix 2001:db8::/48",
		Family: 6,
		Range:  "2001:db8::/48",
		Size:   1 << 16,
		Used:   3,
	}}, p.Pools())
}

func TestPoolBlocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		poolLen int
		alloc   int
		want    int
	}{
		{name: "a /48 delegating /64s", poolLen: 48, alloc: 64, want: 1 << 16},
		{name: "a pool of one block", poolLen: 64, alloc: 64, want: 1},
		{name: "an order that would land on the sign bit", poolLen: 1, alloc: 64, want: math.MaxInt},
		{name: "the largest order the allocator allows", poolLen: 0, alloc: strconv.IntSize - 1, want: math.MaxInt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, poolBlocks(tc.poolLen, tc.alloc))
		})
	}
}

func TestSetupRegistersTheInstance(t *testing.T) {
	h, err := setupPrefix("2001:db8:1::/56", "64")
	require.NoError(t, err)
	require.NotNil(t, h)

	var found leases.Source
	for _, s := range leases.Sources() {
		if s.Name() == "prefix 2001:db8:1::/56" {
			found = s
		}
	}
	require.NotNil(t, found, "setupPrefix must register the instance it built")
	t.Cleanup(func() { leases.Unregister(found) })

	assert.Equal(t, []leases.Pool{{
		Source: "prefix 2001:db8:1::/56",
		Family: 6,
		Range:  "2001:db8:1::/56",
		Size:   256,
	}}, found.Pools())
}
