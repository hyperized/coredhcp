// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leases_test

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
)

type source struct {
	name   string
	leases []leases.Lease
	pools  []leases.Pool
}

func (s *source) Name() string           { return s.name }
func (s *source) Leases() []leases.Lease { return s.leases }
func (s *source) Pools() []leases.Pool   { return s.pools }

func TestSourcesIsACopy(t *testing.T) {
	leases.ResetRegistry(t)

	a := &source{name: "range a"}
	leases.Register(a)

	got := leases.Sources()
	require.Len(t, got, 1)
	got[0] = &source{name: "overwritten"}

	// The caller scribbling on the slice it was handed must not reach the
	// registry: it is a copy, which is what lets a reader hold on to it.
	again := leases.Sources()
	require.Len(t, again, 1)
	assert.Equal(t, "range a", again[0].Name())
}

func TestSourcesSurvivesRegistrationWhileIterating(t *testing.T) {
	leases.ResetRegistry(t)

	leases.Register(&source{name: "range a"})
	snapshot := leases.Sources()

	leases.Register(&source{name: "range b"})
	leases.Unregister(snapshot[0])

	// The snapshot is the caller's, and stays usable and unchanged.
	require.Len(t, snapshot, 1)
	assert.Equal(t, "range a", snapshot[0].Name())
	require.Len(t, leases.Sources(), 1)
	assert.Equal(t, "range b", leases.Sources()[0].Name())
}

func TestSourcesEmptyRegistry(t *testing.T) {
	leases.ResetRegistry(t)

	assert.Empty(t, leases.Sources())
}

func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	leases.ResetRegistry(t)

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func() {
			defer wg.Done()
			s := &source{name: "range " + string(rune('a'+i))}
			leases.Register(s)
			_ = leases.Sources()
			leases.Unregister(s)
		}()
	}
	wg.Wait()

	assert.Empty(t, leases.Sources())
}

func TestLeaseJSONShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lease leases.Lease
		want  string
	}{
		{
			name: "dynamic v4 lease",
			lease: leases.Lease{
				Family:   4,
				Client:   "00:11:22:33:44:55",
				Address:  netip.MustParsePrefix("10.0.0.100/32"),
				Hostname: "laptop",
				Expires:  time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
				Source:   "range leases.sqlite3",
			},
			want: `{"family":4,"client":"00:11:22:33:44:55","address":"10.0.0.100/32",` +
				`"hostname":"laptop","expires":"2026-09-05T12:00:00Z","static":false,` +
				`"source":"range leases.sqlite3"}`,
		},
		{
			name: "static reservation has no expiry",
			lease: leases.Lease{
				Family:  6,
				Client:  "00:11:22:33:44:55",
				Address: netip.MustParsePrefix("2001:db8::10:1/128"),
				Static:  true,
				Source:  "file leases.txt",
			},
			want: `{"family":6,"client":"00:11:22:33:44:55","address":"2001:db8::10:1/128",` +
				`"static":true,"source":"file leases.txt"}`,
		},
		{
			name: "delegated prefix carries its IAID",
			lease: leases.Lease{
				Family:  6,
				Client:  "0001000124f0f1f200112233445566",
				IAID:    1,
				Address: netip.MustParsePrefix("2001:db8:0:1::/64"),
				Expires: time.Date(2026, 9, 5, 13, 30, 0, 0, time.UTC),
				Source:  "prefix 2001:db8::/48",
			},
			want: `{"family":6,"client":"0001000124f0f1f200112233445566","iaid":1,` +
				`"address":"2001:db8:0:1::/64","expires":"2026-09-05T13:30:00Z",` +
				`"static":false,"source":"prefix 2001:db8::/48"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.lease)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(got))

			var back leases.Lease
			require.NoError(t, json.Unmarshal(got, &back))
			assert.Equal(t, tc.lease, back)
		})
	}
}

func TestPoolJSONShape(t *testing.T) {
	got, err := json.Marshal(leases.Pool{
		Source:      "range leases.sqlite3",
		Family:      4,
		Range:       "10.0.0.100-10.0.0.200",
		Size:        101,
		Used:        12,
		Quarantined: 1,
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"source":"range leases.sqlite3","family":4,`+
		`"range":"10.0.0.100-10.0.0.200","size":101,"used":12,"quarantined":1}`, string(got))
}
