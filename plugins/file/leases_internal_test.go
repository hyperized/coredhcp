// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
)

func TestFamilyOf(t *testing.T) {
	assert.Equal(t, uint8(6), familyOf(true))
	assert.Equal(t, uint8(4), familyOf(false))
}

func TestName(t *testing.T) {
	s := &pluginState{name: "file leases.txt"}
	assert.Equal(t, "file leases.txt", s.Name())
}

func TestLeases(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family uint8
		recs   map[string]netip.Addr
		want   []leases.Lease
	}{
		{
			name:   "no reservations",
			family: 4,
			recs:   map[string]netip.Addr{},
			want:   []leases.Lease{},
		},
		{
			name:   "IPv4 reservations",
			family: 4,
			recs: map[string]netip.Addr{
				"00:11:22:33:44:55": netip.MustParseAddr("10.0.0.1"),
				"00:11:22:33:44:56": netip.MustParseAddr("10.0.0.2"),
			},
			want: []leases.Lease{
				{
					Family:  4,
					Client:  "00:11:22:33:44:55",
					Address: netip.MustParsePrefix("10.0.0.1/32"),
					Static:  true,
					Source:  "file leases.txt",
				},
				{
					Family:  4,
					Client:  "00:11:22:33:44:56",
					Address: netip.MustParsePrefix("10.0.0.2/32"),
					Static:  true,
					Source:  "file leases.txt",
				},
			},
		},
		{
			name:   "IPv6 reservations",
			family: 6,
			recs: map[string]netip.Addr{
				"00:11:22:33:44:55": netip.MustParseAddr("2001:db8::10:1"),
			},
			want: []leases.Lease{
				{
					Family:  6,
					Client:  "00:11:22:33:44:55",
					Address: netip.MustParsePrefix("2001:db8::10:1/128"),
					Static:  true,
					Source:  "file leases.txt",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &pluginState{name: "file leases.txt", family: tc.family, recs: tc.recs}

			got := s.Leases()
			slices.SortFunc(got, func(a, b leases.Lease) int {
				return a.Address.Addr().Compare(b.Address.Addr())
			})
			assert.Equal(t, tc.want, got)
			// Nothing here expires, which is what Static means to a reader.
			for _, l := range got {
				assert.True(t, l.Expires.IsZero())
			}
		})
	}
}

func TestLeasesIsASnapshot(t *testing.T) {
	s := &pluginState{
		name:   "file leases.txt",
		family: 4,
		recs:   map[string]netip.Addr{"00:11:22:33:44:55": netip.MustParseAddr("10.0.0.1")},
	}

	got := s.Leases()
	require.Len(t, got, 1)
	got[0].Client = "scribbled on"

	again := s.Leases()
	require.Len(t, again, 1)
	assert.Equal(t, "00:11:22:33:44:55", again[0].Client)
}

func TestPools(t *testing.T) {
	s := &pluginState{
		name:   "file leases.txt",
		family: 4,
		recs:   map[string]netip.Addr{"00:11:22:33:44:55": netip.MustParseAddr("10.0.0.1")},
	}

	// Reservations are not a pool: there is no address space this plugin
	// manages and nothing to compute a utilisation against.
	assert.Nil(t, s.Pools())
}
