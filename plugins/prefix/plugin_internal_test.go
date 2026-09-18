// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
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
	duid1Copy := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	duid2 := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 6}}

	// recordKey is used as a map key across requests, so two distinct DUID
	// objects with the same content must hash the same, not just the same
	// pointer hashed against itself.
	assert.Equal(t, recordKey(duid1), recordKey(duid1Copy))
	assert.NotEqual(t, recordKey(duid1), recordKey(duid2))
}

// fakeClock is a manually advanced clock, so lease lifetimes can be exercised
// without sleeping. It is safe for concurrent use because the background
// sweeper reads it from its own goroutine while the test advances it.
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

// testLeaseDuration is the term every expiry test runs on. The fake clock makes
// the value itself arbitrary, so one shared term keeps the "advance past
// expiry" arithmetic readable.
const testLeaseDuration = time.Hour

// testAllocSize is the delegation size every test carves its pool into, so a
// pool's CIDR length is all that says how many clients it can serve: a /62 is
// four delegations, a /64 exactly one.
const testAllocSize = 64

// newTestPlugin builds an idle plugin instance over pool, carved into /64s, on
// a fake clock. No sweeper is running: a test that wants one calls startSweeper
// itself and owns its lifetime.
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

func asMessage(t *testing.T, result dhcpv6.DHCPv6) *dhcpv6.Message {
	t.Helper()
	msg, ok := result.(*dhcpv6.Message)
	require.True(t, ok, "expected *dhcpv6.Message, got %T", result)
	return msg
}

// duidFor builds a distinct client identifier per n, so a test can bring as
// many clients to the pool as it needs.
func duidFor(n byte) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, n},
	}
}

// solicit runs one SOLICIT carrying a single IA_PD with the given hints and
// returns the prefixes the plugin offered, which is empty when it had none.
func solicit(t *testing.T, h *pluginState, duid dhcpv6.DUID, hints ...*dhcpv6.OptIAPrefix) []*dhcpv6.OptIAPrefix {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, hints...))
	require.NoError(t, err)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	result, stop := h.Handle(req, resp)
	require.NotNil(t, result)
	require.False(t, stop)

	iapds := asMessage(t, result).Options.IAPD()
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

// TestSweepReturnsExhaustedPool is the regression test for the pool that never
// came back: every delegation was written with an expiry that nothing read, and
// allocator.Free was never called anywhere. A pool that has served everyone it
// can must serve again once the delegations have lapsed.
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

// TestReconcileGivesALateClientItsPrefixBack covers reclamation on the request
// path rather than in the sweeper. The lapsed lease is not renewed and handed
// back as if valid; it goes to the pool and is allocated again, hinting at the
// prefix the client used to hold.
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

// TestReconcileDropsAPrefixSomebodyElseTook is the other half: once the lapsed
// prefix is back in the pool it is fair game, and the late client gets whatever
// is left rather than a prefix that is now somebody else's.
func TestReconcileDropsAPrefixSomebodyElseTook(t *testing.T) {
	h, clock := newTestPlugin(t, "2001:db8::/63")

	first := solicit(t, h, duidFor(1))
	require.Len(t, first, 1)
	held := first[0].Prefix

	clock.Advance(testLeaseDuration + time.Second)
	h.sweepOnce()

	// Two clients race for the freed prefix. The first one asking gets it.
	taken := solicit(t, h, duidFor(2), &dhcpv6.OptIAPrefix{Prefix: held})
	require.Len(t, taken, 1)
	require.True(t, held.IP.Equal(taken[0].Prefix.IP))

	late := solicit(t, h, duidFor(1))
	require.Len(t, late, 1)
	assert.False(t, held.IP.Equal(late[0].Prefix.IP), "the late client gets the other prefix")
}

// TestAllocationHintKeepsAClientNamedLength pins that a returning client which
// asked for a particular prefix length is not quietly handed its old prefix
// back instead: the length it named is what reaches the allocator.
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

// TestSweeperReclaimsInBackground runs in a synctest bubble: fake time is
// advanced only once every goroutine in it is durably blocked, so the test
// needs no real waiting.
func TestSweeperReclaimsInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, clock := newTestPlugin(t, "2001:db8::/64")

		require.Len(t, solicit(t, h, duidFor(1)), 1)
		clock.Advance(testLeaseDuration + time.Second)

		h.startSweeper(time.Millisecond)
		defer h.stopSweeper()

		time.Sleep(2 * time.Millisecond) // fake time inside the bubble, returns at once
		synctest.Wait()                  // let the sweep finish before we look

		h.Lock()
		assert.Empty(t, h.Records, "the background sweeper must reclaim the lapsed delegation")
		h.Unlock()

		// Dropping the record alone would not prove reclamation; the prefix has
		// to be allocatable again.
		assert.Len(t, solicit(t, h, duidFor(2)), 1)
	})
}

// freeErrAllocator refuses to take a prefix back, standing in for an allocator
// that has already lost track of one.
type freeErrAllocator struct {
	allocators.Allocator
}

func (freeErrAllocator) Free(net.IPNet) error { return errors.New("simulated double free") }

// TestFreeSurvivesAnAllocatorFailure pins that a lease we have stopped
// honouring is dropped even when the allocator will not take the prefix back.
// Keeping it would mean serving an expiry we have already advertised as past.
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
		{name: "malformed", extra: []string{"forever"}, wantErrSub: `lease duration "forever" is not a duration`},
		{name: "zero", extra: []string{"0s"}, wantErrSub: `lease duration "0s" is not above zero`},
		{name: "negative", extra: []string{"-1h"}, wantErrSub: `lease duration "-1h" is not above zero`},
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

// TestParseOptions pins parseOptions: the defaults it fills in, the two named
// arguments accepted in either order, and the error paths shared by both -
// an unknown key, a key given with no value, a key given twice, and a bad
// value for either one.
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
			wantErrSub: `argument "reap:5m" is not one this plugin takes`,
		},
		{
			name:       "a key with no value",
			extra:      []string{"sweep"},
			wantErrSub: `argument "sweep" is not one this plugin takes`,
		},
		{
			name:       "sweep given twice",
			extra:      []string{"sweep:90s", "sweep:2m"},
			wantErrSub: "argument sweep is given more than once",
		},
		{
			name:       "max-prefixes given twice",
			extra:      []string{"max-prefixes:4", "max-prefixes:8"},
			wantErrSub: "argument max-prefixes is given more than once",
		},
		{
			name:       "malformed sweep interval",
			extra:      []string{"sweep:soon"},
			wantErrSub: "sweep:soon is not a duration",
		},
		{
			name:       "zero sweep interval",
			extra:      []string{"sweep:0s"},
			wantErrSub: "sweep:0s is not above zero",
		},
		{
			name:       "negative sweep interval",
			extra:      []string{"sweep:-1m"},
			wantErrSub: "sweep:-1m is not above zero",
		},
		{
			name:       "non-numeric max-prefixes",
			extra:      []string{"max-prefixes:abc"},
			wantErrSub: "max-prefixes:abc is not a number",
		},
		{
			name:       "zero max-prefixes",
			extra:      []string{"max-prefixes:0"},
			wantErrSub: "max-prefixes:0 is below one",
		},
		{
			name:       "negative max-prefixes",
			extra:      []string{"max-prefixes:-1"},
			wantErrSub: "max-prefixes:-1 is below one",
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

// TestNewPluginStateStartsIdle pins that construction does not start the
// sweeper: setupPrefix starts it only once every other step has succeeded.
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

// TestNewPluginStateMaxPrefixes pins that the max-prefixes argument sets
// pluginState.maxPrefixes, and that leaving it out falls back to
// defaultMaxPrefixes.
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

// buildIAPDMessage returns a message carrying n IA_PD options, one per IAID
// from 1 to n, for exercising iapdsToAnswer without going through a full
// SOLICIT or RELEASE.
func buildIAPDMessage(t *testing.T, n int) *dhcpv6.Message {
	t.Helper()

	msg, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	for i := 1; i <= n; i++ {
		msg.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, byte(i)}})
	}
	return msg
}

// TestIapdsToAnswer pins the per-message IA_PD cap: a message under or at the
// limit is answered in full, and one over it is truncated to the first
// maxIAPDsPerMessage IA_PDs, identified by IAID, so the reply cannot be made
// to grow just by adding more IA_PDs to the request.
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

// buildHints returns n IAPrefix hints inside one IA_PD, each addressed with a
// distinct low byte so a test can tell which ones a truncation kept.
func buildHints(n int) *dhcpv6.OptIAPD {
	iapd := &dhcpv6.OptIAPD{}
	for i := range n {
		ip := make(net.IP, net.IPv6len)
		copy(ip, net.ParseIP("2001:db8::"))
		ip[15] = byte(i)
		iapd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}})
	}
	return iapd
}

func TestRequestedPrefixes(t *testing.T) {
	t.Run("no hints at all synthesises one empty hint", func(t *testing.T) {
		got := requestedPrefixes(&dhcpv6.OptIAPD{})
		require.Len(t, got, 1)
		assert.Equal(t, &net.IPNet{}, got[0].Prefix)
	})

	t.Run("fewer than the cap passes through unchanged", func(t *testing.T) {
		iapd := buildHints(maxHintsPerIAPD - 1)
		want := iapd.Options.Prefixes()

		got := requestedPrefixes(iapd)
		require.Len(t, got, maxHintsPerIAPD-1)
		for i, hint := range got {
			assert.True(t, want[i].Prefix.IP.Equal(hint.Prefix.IP))
		}
	})

	t.Run("more than the cap is truncated to exactly the cap", func(t *testing.T) {
		iapd := buildHints(maxHintsPerIAPD + 4)
		want := iapd.Options.Prefixes()

		got := requestedPrefixes(iapd)
		require.Len(t, got, maxHintsPerIAPD)
		for i, hint := range got {
			assert.True(t, want[i].Prefix.IP.Equal(hint.Prefix.IP), "the kept hints must be the first ones, in order")
		}
	})

	t.Run("a nil Prefix inside the kept portion is normalised", func(t *testing.T) {
		iapd := buildHints(maxHintsPerIAPD)
		iapd.Options.Prefixes()[0].Prefix = nil

		got := requestedPrefixes(iapd)
		require.Len(t, got, maxHintsPerIAPD)
		assert.Equal(t, &net.IPNet{}, got[0].Prefix)
	})
}
