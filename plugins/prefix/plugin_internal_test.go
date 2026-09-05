// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

func TestDup(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)

	dupPrefix := dup(prefix)
	assert.True(t, samePrefix(dupPrefix, prefix))
	// dup must be a deep copy: mutating the source must not affect the copy
	prefix.IP[0] = 0xff
	assert.False(t, dupPrefix.IP.Equal(prefix.IP))
}

func TestSamePrefix(t *testing.T) {
	_, a, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)
	_, b, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)
	_, c, err := net.ParseCIDR("2001:db9::/48")
	require.NoError(t, err)

	tests := []struct {
		name string
		a, b *net.IPNet
		want bool
	}{
		{"both nil", nil, nil, false},
		{"a nil", nil, b, false},
		{"b nil", a, nil, false},
		{"equal prefixes", a, b, true},
		{"different prefixes", a, c, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, samePrefix(tt.a, tt.b))
		})
	}
}

func TestRecordKey(t *testing.T) {
	duid1 := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	duid2 := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 6}}

	assert.Equal(t, recordKey(duid1), recordKey(duid1))
	assert.NotEqual(t, recordKey(duid1), recordKey(duid2))
}

// Manually advanced so lease lifetimes can be exercised without sleeping; the
// mutex covers concurrent access between the test and the background sweeper.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Arbitrary since the clock is fake; shared so "advance past expiry" arithmetic stays consistent.
const testLeaseDuration = time.Hour

// Every pool is carved into /64s, so its CIDR length alone says how many
// clients it can serve (a /62 is four, a /64 one).
const testAllocSize = 64

// No sweeper runs by default; a test that wants one calls startSweeper and owns its lifetime.
func newTestPlugin(t *testing.T, pool string) (*pluginState, *fakeClock) {
	t.Helper()

	_, cidr, err := net.ParseCIDR(pool)
	require.NoError(t, err)
	alloc, err := bitmap.NewBitmapAllocator(*cidr, testAllocSize)
	require.NoError(t, err)

	clock := newFakeClock()
	return &pluginState{
		Records:       make(map[string][]lease),
		allocator:     alloc,
		leaseDuration: testLeaseDuration,
		maxPrefixes:   defaultMaxPrefixes,
		now:           clock.Now,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}, clock
}

func duidFor(n byte) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, n},
	}
}

func solicit(t *testing.T, h *pluginState, duid dhcpv6.DUID, hints ...*dhcpv6.OptIAPrefix) []*dhcpv6.OptIAPrefix {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, hints...))
	require.NoError(t, err)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	result, stop := h.Handle(req, resp)
	require.NotNil(t, result)
	require.False(t, stop)

	iapds := result.(*dhcpv6.Message).Options.IAPD()
	require.Len(t, iapds, 1)
	return iapds[0].Options.Prefixes()
}

func TestTimeNowSeam(t *testing.T) {
	t.Run("defaults to the wall clock", func(t *testing.T) {
		h := &pluginState{}
		assert.WithinDuration(t, time.Now(), h.timeNow(), time.Minute)
	})

	t.Run("uses the injected clock", func(t *testing.T) {
		clock := newFakeClock()
		h := &pluginState{now: clock.Now}
		assert.Equal(t, clock.Now(), h.timeNow())

		clock.Advance(time.Hour)
		assert.Equal(t, clock.Now(), h.timeNow())
	})
}

// A pool that has served everyone it can must serve again once delegations lapse.
func TestSweepReturnsExhaustedPool(t *testing.T) {
	// A /62 carved into /64s is four prefixes.
	h, clock := newTestPlugin(t, "2001:db8::/62")

	for i := range 4 {
		require.Len(t, solicit(t, h, duidFor(byte(i))), 1, "the pool must serve four clients")
	}
	require.Len(t, h.Records, 4)
	assert.Empty(t, solicit(t, h, duidFor(9)), "and nobody after that")

	clock.Advance(testLeaseDuration + time.Second)
	h.sweepOnce()

	assert.Empty(t, h.Records, "a client left holding nothing must be forgotten")
	assert.Len(t, solicit(t, h, duidFor(9)), 1, "the pool serves again")
}

// Reclamation on the request path, not the sweeper: the lapsed lease isn't
// renewed as-is; it's freed and reallocated, incidentally landing on the same prefix.
func TestReconcileGivesALateClientItsPrefixBack(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/62")

	first := solicit(t, h, duidFor(1))
	require.Len(t, first, 1)
	held := first[0].Prefix

	clock.Advance(testLeaseDuration + time.Second)

	second := solicit(t, h, duidFor(1))
	require.Len(t, second, 1)
	assert.True(t, held.IP.Equal(second[0].Prefix.IP), "a client returning late keeps its prefix")

	require.Len(t, h.Records, 1)
	assert.Len(t, h.Records[recordKey(duidFor(1))], 1, "and holds exactly one lease, not two")
}

// Counterpart to the above: once freed, the prefix is fair game, so a late
// client may end up with a different one.
func TestReconcileDropsAPrefixSomebodyElseTook(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/63")

	first := solicit(t, h, duidFor(1))
	require.Len(t, first, 1)
	held := first[0].Prefix

	clock.Advance(testLeaseDuration + time.Second)
	h.sweepOnce()

	// The first of the two clients to ask for the freed prefix gets it.
	taken := solicit(t, h, duidFor(2), &dhcpv6.OptIAPrefix{Prefix: held})
	require.Len(t, taken, 1)
	require.True(t, held.IP.Equal(taken[0].Prefix.IP))

	late := solicit(t, h, duidFor(1))
	require.Len(t, late, 1)
	assert.False(t, held.IP.Equal(late[0].Prefix.IP), "the late client gets the other prefix")
}

// The hinted length must reach the allocator, not shortcut back to the
// client's old prefix.
func TestAllocationHintKeepsAClientNamedLength(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/62")

	require.Len(t, solicit(t, h, duidFor(1)), 1)
	clock.Advance(testLeaseDuration + time.Second)

	got := solicit(t, h, duidFor(1), &dhcpv6.OptIAPrefix{
		Prefix: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(64, 128)},
	})
	require.Len(t, got, 1)
}

func TestUnspecified(t *testing.T) {
	_, full, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		prefix *net.IPNet
		want   bool
	}{
		{"no prefix at all", &net.IPNet{}, true},
		{"the zero address", &net.IPNet{IP: net.IPv6zero}, true},
		{"a length only", &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(60, 128)}, false},
		{"a full prefix", full, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unspecified(&dhcpv6.OptIAPrefix{Prefix: tc.prefix}))
		})
	}
}

func TestSweepOnceWithNothingExpired(t *testing.T) {
	h, _ := newTestPlugin(t, "2001:db8::/62")

	require.Len(t, solicit(t, h, duidFor(1)), 1)
	h.sweepOnce()
	assert.Len(t, h.Records, 1, "a live delegation survives a sweep")
}

// Drives the real ticker at a short interval so a lapsed delegation is
// reclaimed on its own, without any client re-asking.
func TestSweeperReclaimsInBackground(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/64")

	require.Len(t, solicit(t, h, duidFor(1)), 1)
	clock.Advance(testLeaseDuration + time.Second)

	h.startSweeper(time.Millisecond)
	t.Cleanup(h.stopSweeper)

	require.Eventually(t, func() bool {
		h.Lock()
		defer h.Unlock()
		return len(h.Records) == 0
	}, 5*time.Second, 2*time.Millisecond, "the background sweeper must reclaim the lapsed delegation")

	// Dropping the record alone would not prove reclamation; the prefix has
	// to be allocatable again.
	assert.Len(t, solicit(t, h, duidFor(2)), 1)
}

// Refuses to take a prefix back, standing in for an allocator that already
// lost track of it.
type freeErrAllocator struct {
	allocators.Allocator
}

func (freeErrAllocator) Free(net.IPNet) error { return errors.New("simulated double free") }

// A lapsed lease must be dropped even if Free fails; keeping it would mean
// serving an expiry already advertised as past.
func TestFreeSurvivesAnAllocatorFailure(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/62")

	require.Len(t, solicit(t, h, duidFor(1)), 1)
	h.allocator = freeErrAllocator{h.allocator}

	clock.Advance(testLeaseDuration + time.Second)
	h.sweepOnce()
	assert.Empty(t, h.Records)
}

func TestDefaultSweepInterval(t *testing.T) {
	for _, tc := range []struct {
		name          string
		leaseDuration time.Duration
		want          time.Duration
	}{
		{"half of a long lease", time.Hour, 30 * time.Minute},
		{"half of a short lease", 10 * time.Minute, 5 * time.Minute},
		{"exactly at the floor", time.Minute, minSweepInterval},
		{"below the floor", 5 * time.Second, minSweepInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, defaultSweepInterval(tc.leaseDuration))
		})
	}
}

func TestParseLeaseDuration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra      []string
		want       time.Duration
		wantRest   []string
		wantErrSub string
	}{
		{name: "omitted", want: defaultLeaseDuration, wantRest: nil},
		{name: "explicit", extra: []string{"30m"}, want: 30 * time.Minute, wantRest: []string{}},
		{name: "skipped, sweep argument follows", extra: []string{"sweep:45s"}, want: defaultLeaseDuration, wantRest: []string{"sweep:45s"}},
		{name: "skipped, max-prefixes argument follows", extra: []string{"max-prefixes:4"}, want: defaultLeaseDuration, wantRest: []string{"max-prefixes:4"}},
		{name: "followed by a sweep argument", extra: []string{"30m", "sweep:45s"}, want: 30 * time.Minute, wantRest: []string{"sweep:45s"}},
		{name: "malformed", extra: []string{"forever"}, wantErrSub: "invalid lease duration"},
		{name: "zero", extra: []string{"0s"}, wantErrSub: "has to be positive"},
		{name: "negative", extra: []string{"-1h"}, wantErrSub: "has to be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rest, err := parseLeaseDuration(tc.extra)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantRest, rest)
		})
	}
}

func TestParseOptions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra      []string
		want       pluginOptions
		wantErrSub string
	}{
		{
			name: "no arguments falls back to the derived sweep interval and the default max",
			want: pluginOptions{sweepInterval: 30 * time.Minute, maxPrefixes: defaultMaxPrefixes},
		},
		{
			name:  "sweep alone",
			extra: []string{"sweep:90s"},
			want:  pluginOptions{sweepInterval: 90 * time.Second, maxPrefixes: defaultMaxPrefixes},
		},
		{
			name:  "max-prefixes alone",
			extra: []string{"max-prefixes:8"},
			want:  pluginOptions{sweepInterval: 30 * time.Minute, maxPrefixes: 8},
		},
		{
			name:  "sweep followed by max-prefixes",
			extra: []string{"sweep:90s", "max-prefixes:8"},
			want:  pluginOptions{sweepInterval: 90 * time.Second, maxPrefixes: 8},
		},
		{
			name:  "max-prefixes followed by sweep",
			extra: []string{"max-prefixes:8", "sweep:90s"},
			want:  pluginOptions{sweepInterval: 90 * time.Second, maxPrefixes: 8},
		},
		{
			name:       "unknown key",
			extra:      []string{"reap:5m"},
			wantErrSub: "unexpected argument",
		},
		{
			name:       "a key with no value",
			extra:      []string{"sweep"},
			wantErrSub: "unexpected argument",
		},
		{
			name:       "sweep given twice",
			extra:      []string{"sweep:90s", "sweep:2m"},
			wantErrSub: "argument sweep given more than once",
		},
		{
			name:       "max-prefixes given twice",
			extra:      []string{"max-prefixes:4", "max-prefixes:8"},
			wantErrSub: "argument max-prefixes given more than once",
		},
		{
			name:       "malformed sweep interval",
			extra:      []string{"sweep:soon"},
			wantErrSub: "invalid sweep interval",
		},
		{
			name:       "zero sweep interval",
			extra:      []string{"sweep:0s"},
			wantErrSub: "has to be positive",
		},
		{
			name:       "negative sweep interval",
			extra:      []string{"sweep:-1m"},
			wantErrSub: "has to be positive",
		},
		{
			name:       "non-numeric max-prefixes",
			extra:      []string{"max-prefixes:abc"},
			wantErrSub: "invalid prefix maximum",
		},
		{
			name:       "zero max-prefixes",
			extra:      []string{"max-prefixes:0"},
			wantErrSub: "prefix maximum has to be positive",
		},
		{
			name:       "negative max-prefixes",
			extra:      []string{"max-prefixes:-1"},
			wantErrSub: "prefix maximum has to be positive",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOptions(time.Hour, tc.extra)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Construction doesn't start the sweeper; setupPrefix does that only once
// every other step succeeds.
func TestNewPluginStateStartsIdle(t *testing.T) {
	h, err := newPluginState("2001:db8::/48", "64", "30m", "sweep:45s")
	require.NoError(t, err)

	assert.Equal(t, 30*time.Minute, h.leaseDuration)
	assert.Equal(t, 45*time.Second, h.sweepInterval)
	assert.NotNil(t, h.now)

	select {
	case <-h.done:
		t.Fatal("newPluginState must not start the sweeper")
	default:
	}
}

func TestNewPluginStateMaxPrefixes(t *testing.T) {
	t.Run("defaults when absent", func(t *testing.T) {
		h, err := newPluginState("2001:db8::/48", "64")
		require.NoError(t, err)
		assert.Equal(t, defaultMaxPrefixes, h.maxPrefixes)
	})

	t.Run("set from the argument", func(t *testing.T) {
		h, err := newPluginState("2001:db8::/48", "64", "1h", "max-prefixes:9")
		require.NoError(t, err)
		assert.Equal(t, 9, h.maxPrefixes)
	})
}

// Exists to exercise iapdsToAnswer directly, without a full SOLICIT or RELEASE round trip.
func buildIAPDMessage(t *testing.T, n int) *dhcpv6.Message {
	t.Helper()

	msg, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	for i := 1; i <= n; i++ {
		msg.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, byte(i)}})
	}
	return msg
}

// Under or at maxIAPDsPerMessage is answered in full; over it is truncated to
// the first maxIAPDsPerMessage by IAID, so the reply can't be grown just by adding IA_PDs.
func TestIapdsToAnswer(t *testing.T) {
	t.Run("fewer than the limit returns them all", func(t *testing.T) {
		msg := buildIAPDMessage(t, maxIAPDsPerMessage-1)
		assert.Len(t, iapdsToAnswer(msg), maxIAPDsPerMessage-1)
	})

	t.Run("exactly the limit returns them all", func(t *testing.T) {
		msg := buildIAPDMessage(t, maxIAPDsPerMessage)
		assert.Len(t, iapdsToAnswer(msg), maxIAPDsPerMessage)
	})

	t.Run("over the limit keeps only the first ones by IAID", func(t *testing.T) {
		msg := buildIAPDMessage(t, maxIAPDsPerMessage+4)
		got := iapdsToAnswer(msg)
		require.Len(t, got, maxIAPDsPerMessage)
		for i, iapd := range got {
			assert.Equal(t, [4]byte{0, 0, 0, byte(i + 1)}, iapd.IaId)
		}
	})
}
