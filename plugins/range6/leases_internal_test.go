// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"encoding/hex"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
)

// stateWithLeases builds an instance with only the maps Leases and Pools read.
func stateWithLeases(recs map[string]*Record, declined map[string]time.Time) *pluginState {
	return &pluginState{
		name:      "range6 leases6.sqlite3",
		poolRange: poolFirst + "-" + poolLast,
		poolSize:  256,
		Records6:  recs,
		declined:  declined,
	}
}

// byAddress keeps map iteration order out of the assertions.
func byAddress(a, b leases.Lease) int {
	return a.Address.Addr().Compare(b.Address.Addr())
}

func TestName(t *testing.T) {
	p := stateWithLeases(nil, nil)
	assert.Equal(t, "range6 leases6.sqlite3", p.Name())
}

func TestLeases(t *testing.T) {
	expired := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	live := time.Date(2026, 9, 5, 14, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		recs map[string]*Record
		want []leases.Lease
	}{
		{
			name: "no bindings",
			recs: map[string]*Record{},
			want: []leases.Lease{},
		},
		{
			name: "a live and a lapsed binding",
			recs: map[string]*Record{
				"a": {
					DUID:     duidA,
					IAID:     iaidX,
					IP:       net.ParseIP("2001:db8:1::100"),
					expires:  int(live.Unix()),
					hostname: "laptop",
				},
				// Expired but unswept: still reported.
				"b": {
					DUID:    duidB,
					IAID:    iaidX,
					IP:      net.ParseIP("2001:db8:1::101"),
					expires: int(expired.Unix()),
				},
			},
			want: []leases.Lease{
				{
					Family:   6,
					Client:   hex.EncodeToString(duidA),
					IAID:     1,
					Address:  netip.MustParsePrefix("2001:db8:1::100/128"),
					Hostname: "laptop",
					Expires:  live,
					Source:   "range6 leases6.sqlite3",
				},
				{
					Family:  6,
					Client:  hex.EncodeToString(duidB),
					IAID:    1,
					Address: netip.MustParsePrefix("2001:db8:1::101/128"),
					Expires: expired,
					Source:  "range6 leases6.sqlite3",
				},
			},
		},
		{
			name: "a record whose address is not IPv6 is skipped",
			recs: map[string]*Record{
				"c": {DUID: duidA, IAID: iaidX, IP: net.IP{1, 2, 3}, expires: int(live.Unix())},
			},
			want: []leases.Lease{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stateWithLeases(tc.recs, nil).Leases()
			slices.SortFunc(got, byAddress)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLeasesIsASnapshot(t *testing.T) {
	recs := map[string]*Record{
		"a": {DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100"), expires: 1},
	}
	p := stateWithLeases(recs, nil)

	got := p.Leases()
	require.Len(t, got, 1)
	got[0].Hostname = "scribbled on"

	// The caller owns what it was handed, so a later read is unaffected.
	again := p.Leases()
	require.Len(t, again, 1)
	assert.Empty(t, again[0].Hostname)
}

func TestPools(t *testing.T) {
	p := stateWithLeases(
		map[string]*Record{
			"a": {DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100"), expires: 1},
			"b": {DUID: duidB, IAID: iaidX, IP: net.ParseIP("2001:db8:1::101"), expires: 1},
		},
		map[string]time.Time{"2001:db8:1::1ff": time.Now().Add(time.Hour)},
	)

	assert.Equal(t, []leases.Pool{{
		Source:      "range6 leases6.sqlite3",
		Family:      6,
		Range:       poolFirst + "-" + poolLast,
		Size:        256,
		Used:        2,
		Quarantined: 1,
	}}, p.Pools())
}

func TestPoolSizeAsInt(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint64
		want int
	}{
		{name: "a pool", size: 101, want: 101},
		{name: "the largest int fits", size: math.MaxInt, want: math.MaxInt},
		{name: "anything larger saturates", size: math.MaxUint64, want: math.MaxInt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, poolSizeAsInt(tc.size))
		})
	}
}

func TestSetup6RegistersTheInstance(t *testing.T) {
	dbPath := t.TempDir() + "/leases6.db"
	h, err := setup6(dbPath, poolFirst, poolLast, "1h")
	require.NoError(t, err)
	require.NotNil(t, h)

	var found leases.Source
	for _, s := range leases.Sources() {
		if s.Name() == "range6 "+dbPath {
			found = s
		}
	}
	require.NotNil(t, found, "setup6 must register the instance it built")
	t.Cleanup(func() { leases.Unregister(found) })

	require.Len(t, found.Pools(), 1)
	assert.Equal(t, poolFirst+"-"+poolLast, found.Pools()[0].Range)
	assert.True(t, strings.HasPrefix(found.Name(), "range6 "))
}
