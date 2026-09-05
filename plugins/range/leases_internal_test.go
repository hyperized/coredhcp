// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
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

// stateWithLeases builds an instance holding the given records, without a
// database, an allocator or a sweeper: Leases and Pools read the maps and
// nothing else.
func stateWithLeases(recs map[string]*Record, declined map[string]time.Time) *pluginState {
	return &pluginState{
		name:      "range leases.sqlite3",
		poolRange: "10.0.0.1-10.0.0.5",
		poolSize:  5,
		Recordsv4: recs,
		declined:  declined,
	}
}

// byAddress orders leases so a map's iteration order does not leak into the
// assertions.
func byAddress(a, b leases.Lease) int {
	return a.Address.Addr().Compare(b.Address.Addr())
}

func TestName(t *testing.T) {
	p := stateWithLeases(nil, nil)
	assert.Equal(t, "range leases.sqlite3", p.Name())
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
			name: "no leases",
			recs: map[string]*Record{},
			want: []leases.Lease{},
		},
		{
			name: "a live and a lapsed lease",
			recs: map[string]*Record{
				"02:00:00:00:00:01": {IP: net.IP{10, 0, 0, 1}, expires: int(live.Unix()), hostname: "laptop"},
				// Expired but not swept yet: reported all the same, with the
				// expiry that has already passed.
				"02:00:00:00:00:02": {IP: net.IP{10, 0, 0, 2}, expires: int(expired.Unix())},
			},
			want: []leases.Lease{
				{
					Family:   4,
					Client:   "02:00:00:00:00:01",
					Address:  netip.MustParsePrefix("10.0.0.1/32"),
					Hostname: "laptop",
					Expires:  live,
					Source:   "range leases.sqlite3",
				},
				{
					Family:  4,
					Client:  "02:00:00:00:00:02",
					Address: netip.MustParsePrefix("10.0.0.2/32"),
					Expires: expired,
					Source:  "range leases.sqlite3",
				},
			},
		},
		{
			name: "a record whose address is not IPv4 is skipped",
			recs: map[string]*Record{
				"02:00:00:00:00:03": {IP: net.IP{1, 2, 3}, expires: int(live.Unix())},
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
		"02:00:00:00:00:01": {IP: net.IP{10, 0, 0, 1}, expires: 1},
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
			"02:00:00:00:00:01": {IP: net.IP{10, 0, 0, 1}, expires: 1},
			"02:00:00:00:00:02": {IP: net.IP{10, 0, 0, 2}, expires: 1},
		},
		map[string]time.Time{"10.0.0.5": time.Now().Add(time.Hour)},
	)

	assert.Equal(t, []leases.Pool{{
		Source:      "range leases.sqlite3",
		Family:      4,
		Range:       "10.0.0.1-10.0.0.5",
		Size:        5,
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
		{name: "a range", size: 101, want: 101},
		{name: "the largest int fits", size: math.MaxInt, want: math.MaxInt},
		{name: "anything larger saturates", size: math.MaxUint64, want: math.MaxInt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, poolSizeAsInt(tc.size))
		})
	}
}

func TestSetupRegistersTheInstance(t *testing.T) {
	dbPath := t.TempDir() + "/leases.db"
	h, err := setupRange(dbPath, "10.0.0.1", "10.0.0.5", "1h")
	require.NoError(t, err)
	require.NotNil(t, h)

	var found leases.Source
	for _, s := range leases.Sources() {
		if s.Name() == "range "+dbPath {
			found = s
		}
	}
	require.NotNil(t, found, "setupRange must register the instance it built")
	t.Cleanup(func() { leases.Unregister(found) })

	require.Len(t, found.Pools(), 1)
	assert.Equal(t, "10.0.0.1-10.0.0.5", found.Pools()[0].Range)
	assert.True(t, strings.HasPrefix(found.Name(), "range "))
}
