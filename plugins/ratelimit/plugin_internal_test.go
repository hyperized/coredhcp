// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpiana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
)

// epoch is the wall-clock time the fake clock starts at. It carries no
// monotonic reading, which is exactly what a test wants: every duration in
// these tests is one the test set itself.
var epoch = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

// fakeClock is the clock the plugin reads through its now seam, advanced by
// hand so no test ever sleeps.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// warnRecorder collects the summary lines the plugin would have logged. It
// holds a mutex of its own because warn is deliberately called with the
// plugin's own mutex released.
type warnRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (w *warnRecorder) warn(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, fmt.Sprintf(format, args...))
}

func (w *warnRecorder) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.lines)
}

// newTestState builds an instance whose clock and summary log the test owns.
func newTestState(t *testing.T, args ...string) (*state, *fakeClock, *warnRecorder) {
	t.Helper()
	s, err := newState(args...)
	require.NoError(t, err)
	clk := &fakeClock{t: epoch}
	rec := &warnRecorder{}
	s.now = clk.now
	s.warn = rec.warn
	s.lastSummary = epoch
	if s.global != nil {
		s.global.last = epoch
	}
	return s, clk, rec
}

func TestParseRate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          string
		wantInterval time.Duration
		wantPerSec   int
		wantErr      string
	}{
		{name: "per second", raw: "20/s", wantInterval: 50 * time.Millisecond, wantPerSec: 20},
		{name: "one per second", raw: "1/s", wantInterval: time.Second, wantPerSec: 1},
		{name: "per minute", raw: "600/m", wantInterval: 100 * time.Millisecond, wantPerSec: 10},
		{name: "slower than one per second", raw: "1/m", wantInterval: time.Minute, wantPerSec: 0},
		{name: "no period", raw: "20", wantErr: `invalid rate "20", want <n>/s or <n>/m`},
		{name: "not a number", raw: "abc/s", wantErr: `invalid rate "abc", want a whole number`},
		{name: "zero", raw: "0/s", wantErr: "rate 0 out of range, want 1 to 1000000"},
		{name: "negative", raw: "-1/s", wantErr: "rate -1 out of range, want 1 to 1000000"},
		{name: "too large", raw: "1000001/s", wantErr: "rate 1000001 out of range, want 1 to 1000000"},
		{name: "unknown period", raw: "20/h", wantErr: `invalid rate "20/h", want a period of "s" or "m"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			interval, perSec, err := parseRate("rate", tc.raw)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantInterval, interval)
			assert.Equal(t, tc.wantPerSec, perSec)
		})
	}
}

func TestDefaultBurst(t *testing.T) {
	assert.Equal(t, 1, defaultBurst(0))
	assert.Equal(t, 1, defaultBurst(-1))
	assert.Equal(t, 40, defaultBurst(20))
}

func TestParseArgsDefaults(t *testing.T) {
	s, err := parseArgs([]string{"20/s"})
	require.NoError(t, err)
	assert.Equal(t, 50*time.Millisecond, s.interval)
	assert.Equal(t, 40, s.burst)
	assert.Equal(t, modeMAC, s.mode)
	assert.Equal(t, defaultMaxKeys, s.maxKeys)
	assert.Nil(t, s.global)
}

func TestParseArgsOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "documented order", args: []string{"20/s", "burst:50", "per:both", "max:128", "global:2000/s"}},
		{name: "any order", args: []string{"20/s", "global:2000/s", "max:128", "per:both", "burst:50"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parseArgs(tc.args)
			require.NoError(t, err)
			assert.Equal(t, 50, s.burst)
			assert.Equal(t, modeBoth, s.mode)
			assert.Equal(t, 128, s.maxKeys)
			require.NotNil(t, s.global)
			// 2000/s is one token every 500µs, with a burst of 4000.
			assert.Equal(t, 500*time.Microsecond, s.global.interval)
			assert.Equal(t, 2*time.Second, s.global.capacity)
		})
	}
}

func TestParseArgsPerModes(t *testing.T) {
	for raw, want := range map[string]mode{"mac": modeMAC, "source": modeSource, "both": modeBoth} {
		t.Run(raw, func(t *testing.T) {
			s, err := parseArgs([]string{"20/s", perArg + raw})
			require.NoError(t, err)
			assert.Equal(t, want, s.mode)
		})
	}
}

func TestParseArgsErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", args: nil, want: "need a rate as the first argument, for example 20/s or 600/m"},
		{name: "bad rate", args: []string{"fast"}, want: `invalid rate "fast", want <n>/s or <n>/m`},
		{name: "unknown argument", args: []string{"20/s", "nope:1"},
			want: `unknown argument "nope:1", want one of burst:<n>, per:mac|source|both, max:<n> or global:<rate>`},
		{name: "bare argument", args: []string{"20/s", "both"},
			want: `unknown argument "both", want one of burst:<n>, per:mac|source|both, max:<n> or global:<rate>`},
		{name: "burst not a number", args: []string{"20/s", "burst:x"}, want: `invalid burst "x", want a whole number`},
		{name: "burst zero", args: []string{"20/s", "burst:0"}, want: "burst 0 out of range, want 1 to 10000000"},
		{name: "burst too large", args: []string{"20/s", "burst:10000001"}, want: "burst 10000001 out of range, want 1 to 10000000"},
		{name: "per unknown", args: []string{"20/s", "per:vlan"}, want: "invalid per:vlan, want mac, source or both"},
		{name: "max zero", args: []string{"20/s", "max:0"}, want: "max 0 out of range, want 1 to 1048576"},
		{name: "max too large", args: []string{"20/s", "max:1048577"}, want: "max 1048577 out of range, want 1 to 1048576"},
		{name: "global bad rate", args: []string{"20/s", "global:2000"}, want: `invalid global "2000", want <n>/s or <n>/m`},
		{name: "burst twice", args: []string{"20/s", "burst:5", "burst:6"}, want: "burst given more than once"},
		{name: "per twice", args: []string{"20/s", "per:mac", "per:mac"}, want: "per given more than once"},
		{name: "max twice", args: []string{"20/s", "max:5", "max:6"}, want: "max given more than once"},
		{name: "global twice", args: []string{"20/s", "global:1/s", "global:2/s"}, want: "global given more than once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseArgs(tc.args)
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
		})
	}
}

func TestModeString(t *testing.T) {
	assert.Equal(t, "mac", modeMAC.String())
	assert.Equal(t, "source", modeSource.String())
	assert.Equal(t, "both", modeBoth.String())
}

func TestModeParts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     mode
		havePeer bool
		wantID   bool
		wantPeer bool
	}{
		{name: "mac", mode: modeMAC, havePeer: true, wantID: true},
		{name: "source", mode: modeSource, havePeer: true, wantPeer: true},
		{name: "both", mode: modeBoth, havePeer: true, wantID: true, wantPeer: true},
		{name: "mac without peer", mode: modeMAC, wantID: true},
		{name: "source without peer", mode: modeSource, wantID: true},
		{name: "both without peer", mode: modeBoth, wantID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, peer := tc.mode.parts(tc.havePeer)
			assert.Equal(t, tc.wantID, id)
			assert.Equal(t, tc.wantPeer, peer)
		})
	}
}

func TestBucketAllowSpendsExactlyTheBurst(t *testing.T) {
	// Four tokens, one every 50ms.
	l := limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}
	b := &bucket{credit: l.capacity, last: epoch}

	for i := range 4 {
		assert.True(t, b.allow(epoch, l), "token %d should have been available", i+1)
	}
	assert.False(t, b.allow(epoch, l))
	assert.Equal(t, time.Duration(0), b.credit)
}

func TestBucketAllowRefillsAtTheRate(t *testing.T) {
	l := limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}
	b := &bucket{credit: 0, last: epoch}

	// One nanosecond short of a token is still no token.
	assert.False(t, b.allow(epoch.Add(50*time.Millisecond-1), l))
	assert.Equal(t, 50*time.Millisecond-1, b.credit)

	// The nanosecond that completes it pays for exactly one request.
	assert.True(t, b.allow(epoch.Add(50*time.Millisecond), l))
	assert.Equal(t, time.Duration(0), b.credit)
	assert.False(t, b.allow(epoch.Add(50*time.Millisecond), l))
}

func TestBucketAllowClampsToCapacity(t *testing.T) {
	l := limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}
	b := &bucket{credit: 0, last: epoch}

	// An hour of silence buys the burst and not a token more.
	now := epoch.Add(time.Hour)
	for range 4 {
		assert.True(t, b.allow(now, l))
	}
	assert.False(t, b.allow(now, l))
}

func TestBucketAllowIgnoresAClockGoingBackwards(t *testing.T) {
	l := limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}
	b := &bucket{credit: 0, last: epoch}

	assert.False(t, b.allow(epoch.Add(-time.Hour), l))
	assert.Equal(t, time.Duration(0), b.credit)
}

func TestBucketAllowSurvivesAnUnsetLast(t *testing.T) {
	// A zero last makes Sub saturate at the largest Duration; the refill must
	// clamp rather than overflow into a negative credit.
	l := limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}
	b := &bucket{}

	assert.True(t, b.allow(epoch, l))
	assert.Equal(t, 150*time.Millisecond, b.credit)
}

func TestLimitTokens(t *testing.T) {
	assert.Equal(t, int64(4), limit{interval: 50 * time.Millisecond, capacity: 200 * time.Millisecond}.tokens())
}

// keys reads the table's list from the head down, which is most recently seen
// first.
func keys(tbl *table) []string {
	var out []string
	for b := tbl.head; b != nil; b = b.next {
		out = append(out, b.key)
	}
	return out
}

func TestTableEvictsTheLeastRecentlySeen(t *testing.T) {
	tbl := newTable(3)
	for _, k := range []string{"a", "b", "c"} {
		tbl.fetch([]byte(k), epoch, time.Second)
	}
	assert.Equal(t, []string{"c", "b", "a"}, keys(tbl))
	assert.Equal(t, "a", tbl.tail.key)

	// Touching "a" makes "b" the oldest, so "b" is what a fourth key costs.
	tbl.fetch([]byte("a"), epoch, time.Second)
	assert.Equal(t, []string{"a", "c", "b"}, keys(tbl))

	evicted := tbl.tail
	got := tbl.fetch([]byte("d"), epoch, time.Second)
	assert.Same(t, evicted, got, "a full table should reuse the bucket it evicted")
	assert.Equal(t, []string{"d", "a", "c"}, keys(tbl))
	assert.Len(t, tbl.buckets, 3)
	assert.NotContains(t, tbl.buckets, "b")
}

func TestTableTouchOfTheHeadIsANoOp(t *testing.T) {
	tbl := newTable(3)
	tbl.fetch([]byte("a"), epoch, time.Second)
	tbl.fetch([]byte("b"), epoch, time.Second)
	tbl.fetch([]byte("b"), epoch, time.Second)
	assert.Equal(t, []string{"b", "a"}, keys(tbl))
}

func TestTableOfOneEvictsItsOnlyEntry(t *testing.T) {
	tbl := newTable(1)
	first := tbl.fetch([]byte("a"), epoch, time.Second)
	second := tbl.fetch([]byte("b"), epoch, time.Second)
	assert.Same(t, first, second)
	assert.Equal(t, []string{"b"}, keys(tbl))
	assert.Same(t, tbl.head, tbl.tail)
}

func TestTableGivesANewKeyAFullBucket(t *testing.T) {
	tbl := newTable(2)
	b := tbl.fetch([]byte("a"), epoch, 200*time.Millisecond)
	assert.Equal(t, 200*time.Millisecond, b.credit)
	assert.Equal(t, epoch, b.last)
	assert.Equal(t, uint64(0), b.gen)
}

func TestTableEvictionResetsTheReusedBucket(t *testing.T) {
	tbl := newTable(1)
	b := tbl.fetch([]byte("a"), epoch, 200*time.Millisecond)
	b.credit = 0
	b.gen = 7
	reused := tbl.fetch([]byte("b"), epoch.Add(time.Minute), 200*time.Millisecond)
	require.Same(t, b, reused)
	assert.Equal(t, "b", reused.key)
	assert.Equal(t, 200*time.Millisecond, reused.credit)
	assert.Equal(t, epoch.Add(time.Minute), reused.last)
	assert.Equal(t, uint64(0), reused.gen)
}

func TestEvictionResetsWhatTheRateLimitRemembers(t *testing.T) {
	// The documented consequence of an LRU keyed on unauthenticated fields:
	// a client that can push itself out of the table gets a fresh bucket.
	s, _, _ := newTestState(t, "1/m", "burst:1", "max:1")
	assert.True(t, s.allow([]byte("a")))
	assert.False(t, s.allow([]byte("a")))
	assert.True(t, s.allow([]byte("b")))
	assert.True(t, s.allow([]byte("a")), "a was evicted by b, so its bucket is new")
}

func TestAllowGlobalIsSharedAcrossKeys(t *testing.T) {
	// The per-client limit is generous; the shared one allows 4 (two seconds
	// of 2/s) before it bites.
	s, clk, _ := newTestState(t, "100/s", "burst:100", "global:2/s")
	for i := range 4 {
		assert.True(t, s.allow([]byte{byte(i)}), "request %d", i+1)
	}
	assert.False(t, s.allow([]byte{4}))

	// Half a second buys the shared bucket exactly one more request.
	clk.advance(500 * time.Millisecond)
	assert.True(t, s.allow([]byte{5}))
	assert.False(t, s.allow([]byte{6}))
}

func TestPerKeyIsChargedBeforeTheSharedBucket(t *testing.T) {
	s, _, _ := newTestState(t, "1/m", "burst:1", "global:2/s")
	full := s.global.credit

	assert.True(t, s.allow([]byte("a")))
	assert.Equal(t, full-s.globalLimit.interval, s.global.credit)

	// "a" is out of tokens, and being turned away must not cost the shared
	// bucket anything.
	assert.False(t, s.allow([]byte("a")))
	assert.Equal(t, full-s.globalLimit.interval, s.global.credit)
}

func TestNoGlobalBucketPassesEverything(t *testing.T) {
	s, _, _ := newTestState(t, "1/s")
	assert.Nil(t, s.global)
	assert.True(t, s.allowGlobal(epoch))
}

func TestSummaryIsLoggedAtMostOncePerMinute(t *testing.T) {
	s, clk, rec := newTestState(t, "1/m", "burst:1")

	// Two clients each spend their one token and are then turned away.
	require.True(t, s.allow([]byte("a")))
	require.False(t, s.allow([]byte("a")))
	require.True(t, s.allow([]byte("b")))
	require.False(t, s.allow([]byte("b")))

	clk.advance(59 * time.Second)
	require.False(t, s.allow([]byte("a")), "59s buys less than the 60s a token costs")
	assert.Empty(t, rec.all(), "nothing may be logged before the window is up")

	// Two more seconds refill one token for "a", which it spends, and the
	// request after that is the drop that reports the window.
	clk.advance(2 * time.Second)
	require.True(t, s.allow([]byte("a")))
	require.False(t, s.allow([]byte("a")))
	assert.Equal(t, []string{"dropped 4 requests over the last 1m1s, 2 distinct keys"}, rec.all())

	// The counters started over, and the new window counts "a" again.
	assert.Equal(t, uint64(0), s.dropped)
	assert.Equal(t, uint64(0), s.distinct)
	require.False(t, s.allow([]byte("a")))
	assert.Equal(t, uint64(1), s.dropped)
	assert.Equal(t, uint64(1), s.distinct)
	assert.Len(t, rec.all(), 1, "the next summary is a minute away")
}

func TestSummaryCountsAKeyOncePerWindow(t *testing.T) {
	s, _, _ := newTestState(t, "1/m", "burst:1")
	require.True(t, s.allow([]byte("a")))
	for range 5 {
		require.False(t, s.allow([]byte("a")))
	}
	assert.Equal(t, uint64(5), s.dropped)
	assert.Equal(t, uint64(1), s.distinct)
}

func TestSummaryCountsAGlobalOnlyDrop(t *testing.T) {
	s, _, _ := newTestState(t, "100/s", "burst:100", "global:1/m")
	require.True(t, s.allow([]byte("a")))
	require.False(t, s.allow([]byte("b")), "the shared bucket is empty")
	assert.Equal(t, uint64(1), s.dropped)
	assert.Equal(t, uint64(1), s.distinct)
}

// ctxFrom builds the context the server would hand a handler for a request
// from peer, or a bare one when peer is empty.
func ctxFrom(peer string) context.Context {
	if peer == "" {
		return context.Background()
	}
	return handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Peer: netip.MustParseAddrPort(peer),
	})
}

// addr16 is the peer half of a key: an address in the 16-byte form both
// families share.
func addr16(s string) []byte {
	a := netip.MustParseAddrPort(s).Addr().As16()
	return a[:]
}

// withAddr appends the peer half of a key to the identifier half, which is
// what per:both builds.
func withAddr(id []byte, peer string) []byte {
	return append(slices.Clone(id), addr16(peer)...)
}

func TestKey(t *testing.T) {
	const peer = "192.0.2.10:68"
	id := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	long := make([]byte, maxIDLen+40)
	for i := range long {
		long[i] = byte(i)
	}

	for _, tc := range []struct {
		name string
		mode mode
		peer string
		id   []byte
		want []byte
	}{
		{name: "mac", mode: modeMAC, peer: peer, id: id, want: id},
		{name: "source", mode: modeSource, peer: peer, id: id, want: addr16(peer)},
		{name: "both", mode: modeBoth, peer: peer, id: id, want: withAddr(id, peer)},
		{name: "source falls back without request info", mode: modeSource, id: id, want: id},
		{name: "both falls back without request info", mode: modeBoth, id: id, want: id},
		{name: "identifier is clamped", mode: modeBoth, peer: peer, id: long,
			want: withAddr(long[:maxIDLen], peer)},
		{name: "no identifier at all", mode: modeSource, peer: "[2001:db8::1]:547",
			want: addr16("[2001:db8::1]:547")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &state{mode: tc.mode}
			var buf [maxKeyLen]byte
			assert.Equal(t, tc.want, s.key(ctxFrom(tc.peer), &buf, tc.id))
		})
	}
}

func TestKeyIgnoresTheSourcePort(t *testing.T) {
	// A client behind NAT changes port per datagram; keying on it would hand
	// out a fresh bucket every time.
	s := &state{mode: modeSource}
	var one, two [maxKeyLen]byte
	assert.Equal(t,
		s.key(ctxFrom("192.0.2.10:1024"), &one, nil),
		s.key(ctxFrom("192.0.2.10:65000"), &two, nil))
}

func TestClampID(t *testing.T) {
	assert.Len(t, clampID(make([]byte, maxIDLen+1)), maxIDLen)
	assert.Len(t, clampID(make([]byte, 6)), 6)
}

func TestClientID6(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	en := &dhcpv6.DUIDEN{EnterpriseNumber: 42, EnterpriseIdentifier: []byte("coredhcp")}

	t.Run("from a link-layer DUID", func(t *testing.T) {
		req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(&dhcpv6.DUIDLL{
			HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: mac,
		}))
		require.NoError(t, err)
		assert.Equal(t, []byte(mac), clientID6(req))
	})

	t.Run("from the DUID itself", func(t *testing.T) {
		req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(en))
		require.NoError(t, err)
		assert.Equal(t, en.ToBytes(), clientID6(req))
	})

	t.Run("no client ID", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		assert.Nil(t, clientID6(req))
	})

	t.Run("relay with nothing inside", func(t *testing.T) {
		relay := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		assert.Nil(t, clientID6(relay))
	})
}

func TestNewStateBuildsTheGlobalBucketFull(t *testing.T) {
	s, err := newState("20/s", "global:2/s")
	require.NoError(t, err)
	require.NotNil(t, s.global)
	assert.Equal(t, s.globalLimit.capacity, s.global.credit)
	assert.Equal(t, uint64(1), s.gen)
	assert.Equal(t, 2*time.Second, s.perKey.capacity)
}

func TestNewStateRejectsBadArguments(t *testing.T) {
	_, err := newState("nonsense")
	require.Error(t, err)
}

func TestLogLoaded(t *testing.T) {
	// Nothing to assert beyond it running for both shapes: the lines go to
	// the shared logger, which a test has no business redirecting.
	plain, _, _ := newTestState(t, "20/s")
	plain.logLoaded("DHCPv4")
	withGlobal, _, _ := newTestState(t, "20/s", "per:both", "global:2000/s")
	withGlobal.logLoaded("DHCPv6")
}
