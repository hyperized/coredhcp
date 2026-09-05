// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCacheClampsMaxToOne(t *testing.T) {
	cases := []struct {
		name string
		max  int
	}{
		{"zero clamps to one", 0},
		{"negative clamps to one", -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			c := newCache(tc.max)
			c.put("first", lookupResult{found: true}, base.Add(time.Hour))
			c.put("second", lookupResult{found: true}, base.Add(time.Hour))

			assert.Equal(t, 1, c.len())
			_, ok := c.get("first", base)
			assert.False(t, ok, "first key should have been evicted by the clamp to max 1")
			_, ok = c.get("second", base)
			assert.True(t, ok)
		})
	}
}

func TestCacheGetMissOnEmptyCache(t *testing.T) {
	c := newCache(4)
	_, ok := c.get("missing", time.Now())
	assert.False(t, ok)
}

func TestCacheGetHitBeforeExpiry(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCache(4)
	want := lookupResult{v4: netip.MustParsePrefix("10.0.0.1/32"), found: true}
	c.put("k", want, base.Add(time.Minute))

	got, ok := c.get("k", base.Add(30*time.Second))
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestCacheGetExpiryIsInclusive(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCache(4)
	c.put("k", lookupResult{found: true}, base.Add(time.Minute))

	// A get exactly at the expiry instant is already a miss, with the entry gone, not merely stale.
	_, ok := c.get("k", base.Add(time.Minute))
	assert.False(t, ok)
	assert.Equal(t, 0, c.len())
}

func TestCachePutReplacesExistingEntry(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCache(2)

	c.put("a", lookupResult{found: true}, base.Add(time.Minute))
	c.put("b", lookupResult{found: true}, base.Add(time.Minute))

	// a is the LRU entry here; re-putting it must both replace its value and move it back
	// to the front, so the next eviction takes b instead.
	second := lookupResult{v4: netip.MustParsePrefix("10.0.0.9/32"), found: true}
	c.put("a", second, base.Add(2*time.Minute))
	c.put("c", lookupResult{found: true}, base.Add(time.Minute))

	got, ok := c.get("a", base)
	require.True(t, ok)
	assert.Equal(t, second, got)

	_, ok = c.get("b", base)
	assert.False(t, ok, "b should have been evicted as the least recently used entry")
	_, ok = c.get("c", base)
	assert.True(t, ok)
}

func TestCacheLRUEvictionAfterGet(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCache(2)
	c.put("a", lookupResult{found: true}, base.Add(time.Minute))
	c.put("b", lookupResult{found: true}, base.Add(time.Minute))

	// Reading a makes it the MRU entry, so the next insert must evict b instead.
	_, ok := c.get("a", base)
	require.True(t, ok)

	c.put("c", lookupResult{found: true}, base.Add(time.Minute))

	_, ok = c.get("b", base)
	assert.False(t, ok)
	_, ok = c.get("a", base)
	assert.True(t, ok)
	_, ok = c.get("c", base)
	assert.True(t, ok)
	assert.Equal(t, 2, c.len())
}

func TestLookupResultRecord(t *testing.T) {
	v4a := netip.MustParsePrefix("10.0.0.1/32")
	v4b := netip.MustParsePrefix("10.0.0.2/32")
	v6a := netip.MustParsePrefix("2001:db8::1/128")
	v6b := netip.MustParsePrefix("2001:db8::2/128")

	cases := []struct {
		name     string
		prefixes []netip.Prefix
		wantV4   netip.Prefix
		wantV6   netip.Prefix
	}{
		{
			name:     "first IPv4 wins over a later IPv4",
			prefixes: []netip.Prefix{v4a, v4b},
			wantV4:   v4a,
		},
		{
			name:     "first IPv6 wins over a later IPv6",
			prefixes: []netip.Prefix{v6a, v6b},
			wantV6:   v6a,
		},
		{
			name:     "mixed list fills both fields",
			prefixes: []netip.Prefix{v6a, v4a, v6b, v4b},
			wantV4:   v4a,
			wantV6:   v6a,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r lookupResult
			for _, p := range tc.prefixes {
				r.record(p)
			}
			assert.Equal(t, tc.wantV4, r.v4)
			assert.Equal(t, tc.wantV6, r.v6)
		})
	}
}

// TestCacheConcurrentAccess only checks nothing panics or corrupts under `go test -race`; which
// racing put wins is not deterministic, so final contents are not asserted.
func TestCacheConcurrentAccess(t *testing.T) {
	c := newCache(64)
	base := time.Now()

	const goroutines = 8
	const iterations = 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", g%4) // a handful of shared keys so puts and gets collide
			for i := 0; i < iterations; i++ {
				c.put(key, lookupResult{found: true}, base.Add(time.Hour))
				c.get(key, base)
			}
		}(g)
	}
	wg.Wait()

	assert.LessOrEqual(t, c.len(), 64)
}
