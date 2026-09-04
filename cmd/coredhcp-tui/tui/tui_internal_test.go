// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/events"
)

// baseTime is the fixed instant every test builds its events around, so
// nothing here depends on the wall clock.
var baseTime = time.Date(2026, 9, 4, 21, 4, 11, 0, time.UTC)

// ---------------------------------------------------------------------------
// format.go
// ---------------------------------------------------------------------------

// TestClip pins every branch of clip's truncation and sanitisation.
func TestClip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		s     string
		limit int
		want  string
		wantN int
	}{
		{"empty limit", "abc", 0, "", 0},
		{"exact fit", "abc", 3, "abc", 3},
		{"truncation adds ellipsis", "abcd", 3, "ab…", 3},
		{"limit one on longer value", "abcd", 1, "…", 1},
		{"negative limit sanitises without truncating", "a\tb", -1, "a b", 3},
		{"control characters mapped to dot", "a\x01b", 5, "a.b", 3},
		{"tab mapped to space", "a\tb", 5, "a b", 3},
		{"newline mapped to space", "a\nb", 5, "a b", 3},
		{"rune above ceiling replaced", string(rune(0x1F600)), 5, ".", 1},
		{"uiGlyph allowlist passes through", "→", 5, "→", 1},
		{"combining mark replaced", "́", 5, ".", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, n := clip(tc.s, tc.limit)
			assert.Equal(t, tc.want, out)
			assert.Equal(t, tc.wantN, n)
		})
	}
}

// TestClipTail pins clipTail, which keeps an identifier's end rather than its
// start.
func TestClipTail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		s     string
		limit int
		want  string
		wantN int
	}{
		{"limit zero", "aa:bb:cc:dd:ee:ff", 0, "", 0},
		{"limit negative", "aa:bb:cc:dd:ee:ff", -1, "", 0},
		{"shorter than limit", "ab", 5, "ab", 2},
		{"exactly the limit", "abcde", 5, "abcde", 5},
		{"longer than limit keeps the end", "aa:bb:cc:dd:ee:ff", 14, "…b:cc:dd:ee:ff", 14},
		{"limit one on an over-long value", "aa:bb:cc:dd:ee:ff", 1, "…", 1},
		{"invalid utf-8 at the end", "abc\xff", 3, "…c.", 3},
		{"sanitised rune survives without truncation", "a\tbc", 10, "a bc", 4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, n := clipTail(tc.s, tc.limit)
			assert.Equal(t, tc.want, out)
			assert.Equal(t, tc.wantN, n)
		})
	}
}

// TestLineBufWriters exercises every lineBuf writer against a fixed budget.
func TestLineBufWriters(t *testing.T) {
	t.Parallel()

	t.Run("text truncates to the remaining room", func(t *testing.T) {
		t.Parallel()

		l := newLine(5)
		l.text(tagPlain, "hello world")
		assert.Equal(t, "hell…", l.String())
		assert.Equal(t, 0, l.room())
	})

	t.Run("col pads a short value", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.col(tagPlain, "hi", 5)
		assert.Equal(t, "hi   ", l.String())
		assert.Equal(t, 5, l.room())
	})

	t.Run("col with zero width writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.col(tagPlain, "hi", 0)
		assert.Equal(t, "", l.String())
	})

	t.Run("col with no room left writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(0)
		l.col(tagPlain, "hi", 5)
		assert.Equal(t, "", l.String())
	})

	t.Run("col budget running out mid column", func(t *testing.T) {
		t.Parallel()

		l := newLine(3)
		l.col(tagPlain, "hello", 5)
		assert.Equal(t, "he…", l.String())
		assert.Equal(t, 0, l.room())
	})

	t.Run("colRight right aligns and pads on the left", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.colRight(tagPlain, "42", 5)
		assert.Equal(t, "   42", l.String())
	})

	t.Run("colRight with zero width writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.colRight(tagPlain, "42", 0)
		assert.Equal(t, "", l.String())
	})

	t.Run("colRight with no room left writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(0)
		l.colRight(tagPlain, "42", 5)
		assert.Equal(t, "", l.String())
	})

	t.Run("space writes only what still fits", func(t *testing.T) {
		t.Parallel()

		l := newLine(2)
		l.space(5)
		assert.Equal(t, "  ", l.String())
		assert.Equal(t, 0, l.room())
	})

	t.Run("space with nothing to write is a no-op", func(t *testing.T) {
		t.Parallel()

		l := newLine(5)
		l.space(0)
		assert.Equal(t, "", l.String())
	})

	t.Run("tag wraps text with the reset sequence", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.text(tagGood, "ok")
		assert.Equal(t, "[green]ok[-:-:-]", l.String())
	})

	t.Run("tview markup in the input is escaped", func(t *testing.T) {
		t.Parallel()

		l := newLine(20)
		l.text(tagPlain, "[red]x")
		assert.Equal(t, tview.Escape("[red]x"), l.String())
		assert.NotContains(t, l.String(), "[red]")
	})

	t.Run("tail writes the full value when it fits", func(t *testing.T) {
		t.Parallel()

		l := newLine(20)
		l.tail(tagPlain, "aa:bb:cc:dd:ee:ff")
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", l.String())
		assert.Equal(t, 3, l.room())
	})

	t.Run("tail with no budget left is a no-op", func(t *testing.T) {
		t.Parallel()

		l := newLine(0)
		l.tail(tagPlain, "aa:bb:cc:dd:ee:ff")
		assert.Equal(t, "", l.String())
	})

	t.Run("tail keeps the end when it does not fit", func(t *testing.T) {
		t.Parallel()

		l := newLine(5)
		l.tail(tagPlain, "aa:bb:cc:dd:ee:ff")
		assert.Equal(t, "…e:ff", l.String())
	})

	t.Run("cell pads out whatever the callback leaves", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.cell(6, func(b *lineBuf) { b.text(tagPlain, "ab") })
		assert.Equal(t, "ab    ", l.String())
		assert.Equal(t, 4, l.room())
	})

	t.Run("cell with zero width writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.cell(0, func(b *lineBuf) { b.text(tagPlain, "ab") })
		assert.Equal(t, "", l.String())
	})

	t.Run("cell with no room left writes nothing", func(t *testing.T) {
		t.Parallel()

		l := newLine(0)
		l.cell(6, func(b *lineBuf) { b.text(tagPlain, "ab") })
		assert.Equal(t, "", l.String())
	})

	t.Run("String returns the accumulated row", func(t *testing.T) {
		t.Parallel()

		l := newLine(10)
		l.text(tagPlain, "a")
		l.space(1)
		l.text(tagPlain, "b")
		assert.Equal(t, "a b", l.String())
	})
}

// TestHumanCount pins the thousands-separator formatting.
func TestHumanCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    uint64
		want string
	}{
		{"zero", 0, "0"},
		{"under a thousand", 999, "999"},
		{"exactly a thousand", 1000, "1,000"},
		{"six digits no remainder", 123456, "123,456"},
		{"seven digits with remainder", 1234567, "1,234,567"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, humanCount(tc.n))
		})
	}
}

// TestHumanDuration pins every duration bucket.
func TestHumanDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "-"},
		{"negative", -time.Second, "-"},
		{"under a microsecond", 500 * time.Nanosecond, "<1µs"},
		{"microseconds", 250 * time.Microsecond, "250µs"},
		{"milliseconds", 12300 * time.Microsecond, "12.3ms"},
		{"seconds", 2500 * time.Millisecond, "2.5s"},
		{"minutes", 90 * time.Second, "1m30s"},
		{"minutes exact", time.Minute, "1m00s"},
		{"hours", 2*time.Hour + 5*time.Minute, "2h05m"},
		{"hours exact", time.Hour, "1h00m"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, humanDuration(tc.d))
		})
	}
}

// TestPad2 pins the zero-padding helper.
func TestPad2(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00", pad2(0))
	assert.Equal(t, "09", pad2(9))
	assert.Equal(t, "42", pad2(42))
}

// TestHumanUptime pins hh:mm:ss rendering, including the negative floor and
// running past 24 hours.
func TestHumanUptime(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00:00:00", humanUptime(-time.Second))
	assert.Equal(t, "01:02:03", humanUptime(time.Hour+2*time.Minute+3*time.Second))
	assert.Equal(t, "30:00:00", humanUptime(30*time.Hour))
}

// TestHumanSince pins the "last seen" rendering.
func TestHumanSince(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"zero time", time.Time{}, "-"},
		{"sub second", baseTime.Add(-500 * time.Millisecond), "now"},
		{"minutes ago", baseTime.Add(-90 * time.Second), "1m30s ago"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, humanSince(baseTime, tc.t))
		})
	}
}

// TestHumanRemaining pins the lease countdown.
func TestHumanRemaining(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		expiry time.Time
		want   string
	}{
		{"zero expiry", time.Time{}, "-"},
		{"expired", baseTime.Add(-time.Second), "expired"},
		{"expires now", baseTime, "expired"},
		{"counting down", baseTime.Add(90 * time.Second), "1m30s"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, humanRemaining(baseTime, tc.expiry))
		})
	}
}

// TestAddrText pins how one address prefix renders.
func TestAddrText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    netip.Prefix
		want string
	}{
		{"invalid prefix", netip.Prefix{}, ""},
		{"v4 host route", netip.MustParsePrefix("10.0.0.5/32"), "10.0.0.5"},
		{"v6 host route", netip.MustParsePrefix("2001:db8::5/128"), "2001:db8::5"},
		{"shorter prefix", netip.MustParsePrefix("10.0.0.0/24"), "10.0.0.0/24"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, addrText(tc.p))
		})
	}
}

// TestJoinAddrs pins how a reply's address list is joined, including the
// "+N" suffix past maxShownAddrs.
func TestJoinAddrs(t *testing.T) {
	t.Parallel()

	host := func(s string) netip.Prefix { return netip.MustParsePrefix(s + "/32") }

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", joinAddrs(nil))
	})

	t.Run("one address", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "10.0.0.1", joinAddrs([]netip.Prefix{host("10.0.0.1")}))
	})

	t.Run("more than maxShownAddrs adds a count", func(t *testing.T) {
		t.Parallel()

		addrs := []netip.Prefix{host("10.0.0.1"), host("10.0.0.2"), host("10.0.0.3"), host("10.0.0.4"), host("10.0.0.5")}
		assert.Equal(t, "10.0.0.1,10.0.0.2,10.0.0.3,+2", joinAddrs(addrs))
	})
}

// TestSparkline pins the block-ramp rendering.
func TestSparkline(t *testing.T) {
	t.Parallel()

	t.Run("empty values", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", sparkline(nil, 10, 5))
	})

	t.Run("zero width", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", sparkline([]uint32{1, 2}, 10, 0))
	})

	t.Run("zero peak renders the lowest step", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "▁▁▁", sparkline([]uint32{1, 2, 3}, 0, 3))
	})

	t.Run("values longer than width keep the newest", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "▁█", sparkline([]uint32{10, 0, 10}, 10, 2))
	})

	t.Run("a non-zero value never renders as the lowest glyph", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "▂", sparkline([]uint32{1}, 1000, 1))
	})
}

// TestSparkRune pins the per-value glyph selection.
func TestSparkRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    uint32
		peak uint32
		want rune
	}{
		{"zero value", 0, 100, '▁'},
		{"zero peak", 5, 0, '▁'},
		{"half of peak", 50, 100, '▅'},
		{"at peak", 100, 100, '█'},
		{"equal small values", 1, 1, '█'},
		{"tiny fraction of a large peak", 1, 1000, '▂'},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, sparkRune(tc.v, tc.peak))
		})
	}
}

// TestVisible pins the scroll window a pane renders.
func TestVisible(t *testing.T) {
	t.Parallel()

	lines := []string{"a", "b", "c", "d", "e"}

	t.Run("height zero shows nothing", func(t *testing.T) {
		t.Parallel()
		out, start := visible(lines, 0, 0, false)
		assert.Nil(t, out)
		assert.Equal(t, 0, start)
	})

	t.Run("empty lines shows nothing", func(t *testing.T) {
		t.Parallel()
		out, start := visible(nil, 3, 0, false)
		assert.Nil(t, out)
		assert.Equal(t, 0, start)
	})

	t.Run("follow pins to the bottom", func(t *testing.T) {
		t.Parallel()
		out, start := visible(lines, 2, 0, true)
		assert.Equal(t, []string{"d", "e"}, out)
		assert.Equal(t, 3, start)
	})

	t.Run("offset clamped past the end", func(t *testing.T) {
		t.Parallel()
		out, start := visible(lines, 2, 99, false)
		assert.Equal(t, []string{"d", "e"}, out)
		assert.Equal(t, 3, start)
	})

	t.Run("negative offset clamped to zero", func(t *testing.T) {
		t.Parallel()
		out, start := visible(lines, 2, -5, false)
		assert.Equal(t, []string{"a", "b"}, out)
		assert.Equal(t, 0, start)
	})

	t.Run("offset within range is honoured", func(t *testing.T) {
		t.Parallel()
		out, start := visible(lines, 2, 1, false)
		assert.Equal(t, []string{"b", "c"}, out)
		assert.Equal(t, 1, start)
	})
}

// ---------------------------------------------------------------------------
// model.go
// ---------------------------------------------------------------------------

// TestRing pins the FIFO ring's push, ordering and reset behaviour.
func TestRing(t *testing.T) {
	t.Parallel()

	t.Run("push under capacity keeps arrival order", func(t *testing.T) {
		t.Parallel()

		r := newRing[int](5)
		r.push(1)
		r.push(2)
		assert.Equal(t, []int{1, 2}, r.items())
	})

	t.Run("push over capacity drops the oldest", func(t *testing.T) {
		t.Parallel()

		r := newRing[int](3)
		for i := 1; i <= 5; i++ {
			r.push(i)
		}

		assert.Equal(t, []int{3, 4, 5}, r.items())
	})

	t.Run("reset empties the ring", func(t *testing.T) {
		t.Parallel()

		r := newRing[int](3)
		r.push(1)
		r.push(2)
		r.reset()
		assert.Empty(t, r.items())

		r.push(9)
		assert.Equal(t, []int{9}, r.items())
	})
}

// TestRateRing pins the per-second bucket ring: priming, advancing,
// clearing and reading it back as a series.
func TestRateRing(t *testing.T) {
	t.Parallel()

	t.Run("priming sets the head second without clearing", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		series := r.series(baseTime)
		assert.EqualValues(t, 1, sum(series))
	})

	t.Run("same second accumulates in one bucket", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		r.add(baseTime.Add(500 * time.Millisecond))
		series := r.series(baseTime)
		assert.EqualValues(t, 2, peak(series))
	})

	t.Run("a step backwards lands in the head bucket", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		r.add(baseTime.Add(-time.Second))
		series := r.series(baseTime)
		assert.EqualValues(t, 2, sum(series))
	})

	t.Run("a step of a few seconds zeroes what it passed", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		r.add(baseTime.Add(3 * time.Second))
		series := r.series(baseTime.Add(3 * time.Second))
		assert.EqualValues(t, 2, sum(series), "both events still count, only the skipped buckets read zero")
		assert.EqualValues(t, 1, series[len(series)-1], "the newest bucket holds only the second event")
		assert.EqualValues(t, 0, series[len(series)-2], "a passed-over bucket reads zero")
	})

	t.Run("a step past rateBuckets clears everything", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		r.add(baseTime.Add((rateBuckets + 5) * time.Second))
		series := r.series(baseTime.Add((rateBuckets + 5) * time.Second))
		assert.EqualValues(t, 1, sum(series))
	})

	t.Run("series ages to now and reads oldest first", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		series := r.series(baseTime.Add(2 * time.Second))
		require.Len(t, series, rateBuckets)
		assert.EqualValues(t, 1, series[len(series)-3])
		assert.EqualValues(t, 0, series[len(series)-1])
	})

	t.Run("reset drops history without moving the head second", func(t *testing.T) {
		t.Parallel()

		var r rateRing

		r.add(baseTime)
		r.add(baseTime)
		r.reset()
		assert.EqualValues(t, 0, sum(r.series(baseTime)))

		r.add(baseTime)
		assert.EqualValues(t, 1, sum(r.series(baseTime)))
	})
}

// TestSumPeak pins the two series aggregates.
func TestSumPeak(t *testing.T) {
	t.Parallel()

	values := []uint32{1, 5, 3, 0, 2}
	assert.EqualValues(t, 11, sum(values))
	assert.EqualValues(t, 5, peak(values))
	assert.EqualValues(t, 0, sum(nil))
	assert.EqualValues(t, 0, peak(nil))
}

// TestFamilyCountersAdd pins how one request folds into the family tallies,
// including the bumpKey key cap.
func TestFamilyCountersAdd(t *testing.T) {
	t.Parallel()

	t.Run("counts requests in and replies out", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{Type: "DISCOVER", ReplyType: "OFFER"})
		assert.EqualValues(t, 1, c.total)
		assert.EqualValues(t, 1, c.in["DISCOVER"])
		assert.EqualValues(t, 1, c.out["OFFER"])
	})

	t.Run("an empty reply type is not counted out", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{Type: "DISCOVER"})
		assert.Empty(t, c.out)
	})

	t.Run("an empty type becomes a question mark", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{})
		assert.EqualValues(t, 1, c.in["?"])
	})

	t.Run("every outcome branch is tallied", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{Outcome: events.OutcomeReplied})
		c.add(events.Request{Outcome: events.OutcomeDropped})
		c.add(events.Request{Outcome: events.OutcomeParseError})
		c.add(events.Request{Outcome: events.OutcomeUnsupported})
		c.add(events.Request{Outcome: events.OutcomeSendError})

		assert.EqualValues(t, 5, c.total)
		assert.EqualValues(t, 1, c.dropped)
		assert.EqualValues(t, 1, c.parseErrs)
		assert.EqualValues(t, 1, c.unsupported)
		assert.EqualValues(t, 1, c.sendErrs)
	})

	t.Run("the path array counts every valid path", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{Path: events.PathNone})
		c.add(events.Request{Path: events.PathUnicast})
		c.add(events.Request{Path: events.PathBroadcast})
		c.add(events.Request{Path: events.PathLayer2})

		assert.EqualValues(t, 1, c.paths[events.PathNone])
		assert.EqualValues(t, 1, c.paths[events.PathUnicast])
		assert.EqualValues(t, 1, c.paths[events.PathBroadcast])
		assert.EqualValues(t, 1, c.paths[events.PathLayer2])
	})

	t.Run("the map cap folds extra keys into other", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		for i := range maxTypeKeys + 3 {
			c.add(events.Request{Type: fmt.Sprintf("T%02d", i)})
		}

		assert.LessOrEqual(t, len(c.in), maxTypeKeys+1)
		assert.EqualValues(t, 3, c.in["other"])
	})
}

// TestFamilyCountersClone pins that clone is a deep copy: mutating the
// clone's maps must not reach the original.
func TestFamilyCountersClone(t *testing.T) {
	t.Parallel()

	c := newFamilyCounters()
	c.add(events.Request{Type: "DISCOVER", ReplyType: "OFFER"})

	clone := c.clone()
	clone.in["INJECTED"] = 99
	clone.out["INJECTED"] = 99

	assert.NotContains(t, c.in, "INJECTED")
	assert.NotContains(t, c.out, "INJECTED")
	assert.Equal(t, c.total, clone.total)
}

// TestPaneIDFollowsAndTitle pins the follow flag and the border title for
// every pane, including the sentinel paneCount value.
func TestPaneIDFollowsAndTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		id         paneID
		wantFollow bool
		wantTitle  string
	}{
		{"traffic", paneTraffic, true, "traffic"},
		{"leases", paneLeases, false, "leases"},
		{"plugins", panePlugins, false, "plugins"},
		{"log", paneLog, true, "log"},
		{"sentinel", paneCount, false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantFollow, tc.id.follows())
			assert.Equal(t, tc.wantTitle, tc.id.title())
		})
	}
}

// TestNewModelAddListenerAddPlugin pins that a fresh model records listeners
// and plugins and marks itself dirty.
func TestNewModelAddListenerAddPlugin(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v0.2.0", 10, 10, 10)

	m.addListener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"})
	m.addPlugin(events.Plugin{Family: events.FamilyV4, Name: "range", Args: []string{"a", "b"}})

	snap, ok := m.snapshot(baseTime, false)
	require.True(t, ok)
	require.Len(t, snap.listeners, 1)
	assert.Equal(t, "0.0.0.0:67", snap.listeners[0].Address)
	require.Len(t, snap.chains[events.FamilyV4], 1)
	assert.Equal(t, "range", snap.chains[events.FamilyV4][0].name)
}

// TestAddListenerClipsFields pins that a listener's strings are cut down
// before they are stored.
func TestAddListenerClipsFields(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	long := strings.Repeat("x", maxNameLen+20)
	m.addListener(events.Listener{Address: long, Interface: long})

	require.Len(t, m.listeners, 1)
	assert.LessOrEqual(t, len([]rune(m.listeners[0].Address)), maxNameLen)
	assert.LessOrEqual(t, len([]rune(m.listeners[0].Interface)), maxWordLen)
}

// TestAddPluginClipsName pins that a plugin's name is cut down before it is
// stored, while its arguments travel unmodified into the chain link.
func TestAddPluginClipsName(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	long := strings.Repeat("y", maxWordLen+20)
	m.addPlugin(events.Plugin{Family: events.FamilyV4, Name: long, Args: []string{"a"}})

	require.Len(t, m.chains[events.FamilyV4], 1)
	assert.LessOrEqual(t, len([]rune(m.chains[events.FamilyV4][0].name)), maxWordLen)
	assert.Equal(t, []string{"a"}, m.chains[events.FamilyV4][0].args)
}

// TestModelAddRequest pins that a handled request updates every part of the
// model, and that a zero Time is filled in from the passed clock time.
func TestModelAddRequest(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	m.addRequest(baseTime, events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
		Outcome: events.OutcomeReplied,
	})

	snap, ok := m.snapshot(baseTime, false)
	require.True(t, ok)
	require.Len(t, snap.traffic, 1)
	assert.EqualValues(t, 1, snap.tot.requests)
	assert.True(t, snap.tot.lastRequest.Equal(baseTime))
	assert.EqualValues(t, 1, snap.counts[events.FamilyV4].total)
}

// TestModelAddRequestZeroTime pins that an event with a zero Time is
// stamped with the clock time it was handed.
func TestModelAddRequestZeroTime(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	m.addRequest(baseTime, events.Request{Family: events.FamilyV4, Type: "DISCOVER"})

	snap, ok := m.snapshot(baseTime, false)
	require.True(t, ok)
	require.Len(t, snap.traffic, 1)
	assert.True(t, snap.traffic[0].Time.Equal(baseTime))
}

// TestBoundRequest pins that boundRequest cuts strings and the address list
// down, and that the resulting Addresses slice does not alias the caller's.
func TestBoundRequest(t *testing.T) {
	t.Parallel()

	t.Run("long strings are clipped", func(t *testing.T) {
		t.Parallel()

		long := strings.Repeat("z", 500)
		out := boundRequest(events.Request{
			Interface: long, Type: long, ReplyType: long, Plugin: long,
			ClientID: long, Hostname: long, Error: long,
		})

		assert.LessOrEqual(t, len([]rune(out.Interface)), maxWordLen)
		assert.LessOrEqual(t, len([]rune(out.Type)), maxWordLen)
		assert.LessOrEqual(t, len([]rune(out.ReplyType)), maxWordLen)
		assert.LessOrEqual(t, len([]rune(out.Plugin)), maxWordLen)
		assert.LessOrEqual(t, len([]rune(out.ClientID)), maxIDLen)
		assert.LessOrEqual(t, len([]rune(out.Hostname)), maxNameLen)
		assert.LessOrEqual(t, len([]rune(out.Error)), maxErrLen)
	})

	t.Run("more than maxAddrs addresses are cut", func(t *testing.T) {
		t.Parallel()

		addrs := make([]netip.Prefix, maxAddrs+3)
		for i := range addrs {
			addrs[i] = netip.MustParsePrefix(fmt.Sprintf("10.0.0.%d/32", i+1))
		}

		out := boundRequest(events.Request{Addresses: addrs})
		assert.Len(t, out.Addresses, maxAddrs)
	})

	t.Run("the Addresses slice is cloned", func(t *testing.T) {
		t.Parallel()

		addrs := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.2/32")}
		out := boundRequest(events.Request{Addresses: addrs})

		addrs[0] = netip.MustParsePrefix("192.168.0.9/32")

		assert.Equal(t, "10.0.0.1", addrText(out.Addresses[0]))
	})
}

// TestModelFamily pins that the per-family counters map is capped at
// maxFamilies, past which a throwaway counters value is handed back.
func TestModelFamily(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)

	for i := range maxFamilies {
		m.family(events.Family(i))
	}

	require.Len(t, m.counts, maxFamilies)

	overflow := events.Family(maxFamilies)
	first := m.family(overflow)
	second := m.family(overflow)

	assert.Len(t, m.counts, maxFamilies)
	assert.NotSame(t, first, second)
}

// TestModelRecordOutcome pins the server-wide tallies and the error history
// timestamps for every outcome branch.
func TestModelRecordOutcome(t *testing.T) {
	t.Parallel()

	t.Run("dropped", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordOutcome(events.Request{Outcome: events.OutcomeDropped})
		assert.EqualValues(t, 1, m.tot.dropped)
	})

	t.Run("parse error marks the soft error clock", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordOutcome(events.Request{Time: baseTime, Outcome: events.OutcomeParseError})
		assert.EqualValues(t, 1, m.tot.errors)
		assert.True(t, m.tot.lastSoftErr.Equal(baseTime))
		assert.EqualValues(t, 1, sum(m.errRate.series(baseTime)))
	})

	t.Run("unsupported marks the soft error clock", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordOutcome(events.Request{Time: baseTime, Outcome: events.OutcomeUnsupported})
		assert.True(t, m.tot.lastSoftErr.Equal(baseTime))
	})

	t.Run("send error marks the send error clock", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordOutcome(events.Request{Time: baseTime, Outcome: events.OutcomeSendError})
		assert.EqualValues(t, 1, m.tot.errors)
		assert.True(t, m.tot.lastSendErr.Equal(baseTime))
	})

	t.Run("replied touches nothing", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordOutcome(events.Request{Time: baseTime, Outcome: events.OutcomeReplied})
		assert.Zero(t, m.tot.dropped)
		assert.Zero(t, m.tot.errors)
	})
}

// TestModelRecordChain pins how a request's outcome is attributed to the
// plugins in its family's chain.
func TestModelRecordChain(t *testing.T) {
	t.Parallel()

	newChain := func() map[events.Family][]*chainLink {
		return map[events.Family][]*chainLink{
			events.FamilyV4: {{name: "a"}, {name: "b"}, {name: "c"}},
		}
	}

	t.Run("a family with no chain is a no-op", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		require.NotPanics(t, func() {
			m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeReplied})
		})
	})

	t.Run("position zero marks every link reached and attributes nothing", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.chains = newChain()
		m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeReplied, Position: 0})

		for _, l := range m.chains[events.FamilyV4] {
			assert.EqualValues(t, 1, l.reached)
			assert.Zero(t, l.replied)
			assert.Zero(t, l.dropped)
		}
	})

	t.Run("an out-of-range position attributes nothing", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.chains = newChain()
		m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeReplied, Position: 99})

		for _, l := range m.chains[events.FamilyV4] {
			assert.EqualValues(t, 1, l.reached)
			assert.Zero(t, l.replied)
			assert.Zero(t, l.dropped)
		}
	})

	t.Run("a stopping position marks 1..p and attributes the stop to link p", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.chains = newChain()
		m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeReplied, Position: 2})

		links := m.chains[events.FamilyV4]
		assert.EqualValues(t, 1, links[0].reached)
		assert.EqualValues(t, 1, links[1].reached)
		assert.Zero(t, links[2].reached)
		assert.EqualValues(t, 1, links[1].replied)
	})

	t.Run("a stopping position with a send error still counts as replied", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.chains = newChain()
		m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeSendError, Position: 1})

		assert.EqualValues(t, 1, m.chains[events.FamilyV4][0].replied)
	})

	t.Run("a stopping position with a drop is attributed as dropped", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.chains = newChain()
		m.recordChain(events.Request{Family: events.FamilyV4, Outcome: events.OutcomeDropped, Position: 3})

		assert.EqualValues(t, 1, m.chains[events.FamilyV4][2].dropped)
	})

	t.Run("parse and unsupported outcomes reach nobody", func(t *testing.T) {
		t.Parallel()

		for _, outcome := range []events.Outcome{events.OutcomeParseError, events.OutcomeUnsupported} {
			m := newModel(baseTime, "v", 10, 10, 10)
			m.chains = newChain()
			m.recordChain(events.Request{Family: events.FamilyV4, Outcome: outcome, Position: 2})

			for _, l := range m.chains[events.FamilyV4] {
				assert.Zero(t, l.reached)
			}
		}
	})
}

// TestModelAddLog pins that a log line is clipped and stored with its
// arrival time, and marks the model dirty.
func TestModelAddLog(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	m.addLog(baseTime, strings.Repeat("x", maxLogLineLen+50))

	require.Len(t, m.logs.items(), 1)
	entry := m.logs.items()[0]
	assert.True(t, entry.at.Equal(baseTime))
	assert.LessOrEqual(t, len([]rune(entry.raw)), maxLogLineLen)
}

// TestModelSnapshot pins the dirty flag protocol and the paused traffic
// copy.
func TestModelSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("not dirty and not forced returns false", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		_, ok := m.snapshot(baseTime, false)
		assert.False(t, ok)
	})

	t.Run("dirty returns true and clears the flag", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.addListener(events.Listener{Family: events.FamilyV4})

		_, ok := m.snapshot(baseTime, false)
		require.True(t, ok)
		assert.False(t, m.dirty)

		_, ok = m.snapshot(baseTime, false)
		assert.False(t, ok)
	})

	t.Run("forced returns true even when clean", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		_, ok := m.snapshot(baseTime, true)
		assert.True(t, ok)
	})

	t.Run("paused snapshot returns the frozen traffic copy", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.addRequest(baseTime, events.Request{Family: events.FamilyV4, Type: "DISCOVER"})
		m.togglePause()
		m.addRequest(baseTime, events.Request{Family: events.FamilyV4, Type: "REQUEST"})

		snap, ok := m.snapshot(baseTime, false)
		require.True(t, ok)
		require.Len(t, snap.traffic, 1)
		assert.Equal(t, "DISCOVER", snap.traffic[0].Type)
	})
}

// TestCloneChainsCloneCounts pins that both clone helpers are deep copies.
func TestCloneChainsCloneCounts(t *testing.T) {
	t.Parallel()

	t.Run("cloneChains copies links and their arguments", func(t *testing.T) {
		t.Parallel()

		src := map[events.Family][]*chainLink{
			events.FamilyV4: {{name: "range", args: []string{"a"}, reached: 3}},
		}

		out := cloneChains(src)
		out[events.FamilyV4][0].reached = 99
		out[events.FamilyV4][0].args[0] = "mutated"

		assert.EqualValues(t, 3, src[events.FamilyV4][0].reached)
		assert.Equal(t, "a", src[events.FamilyV4][0].args[0])
	})

	t.Run("cloneCounts copies the per-family maps", func(t *testing.T) {
		t.Parallel()

		c := newFamilyCounters()
		c.add(events.Request{Type: "DISCOVER"})
		src := map[events.Family]*familyCounters{events.FamilyV4: c}

		out := cloneCounts(src)
		clone := out[events.FamilyV4]
		clone.in["INJECTED"] = 1

		assert.NotContains(t, c.in, "INJECTED")
	})
}

// TestModelSetGeometry pins that a pane's scroll geometry is written back
// under lock.
func TestModelSetGeometry(t *testing.T) {
	t.Parallel()

	m := newModel(baseTime, "v", 10, 10, 10)
	m.setGeometry(paneTraffic, 5, 50, 10)

	assert.Equal(t, 5, m.panes[paneTraffic].start)
	assert.Equal(t, 50, m.panes[paneTraffic].total)
	assert.Equal(t, 10, m.panes[paneTraffic].height)
}

// ---------------------------------------------------------------------------
// leases.go
// ---------------------------------------------------------------------------

// TestLeaseTransitionV4 pins every DHCPv4 rule from the README's "Where the
// lease states come from" table.
func TestLeaseTransitionV4(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    events.Request
		want leaseState
	}{
		{
			"discover offer issues a lease",
			events.Request{Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER", Outcome: events.OutcomeReplied},
			leaseOffered,
		},
		{
			"request ack with an address confirms it",
			events.Request{
				Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK", Outcome: events.OutcomeReplied,
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
			},
			leaseConfirmed,
		},
		{
			"request ack with no address confirms nothing",
			events.Request{Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK", Outcome: events.OutcomeReplied},
			leaseNone,
		},
		{
			"request nak refuses",
			events.Request{Family: events.FamilyV4, Type: "REQUEST", ReplyType: "NAK", Outcome: events.OutcomeReplied},
			leaseRefused,
		},
		{
			"release counts regardless of outcome",
			events.Request{Family: events.FamilyV4, Type: "RELEASE", Outcome: events.OutcomeDropped},
			leaseReleased,
		},
		{
			"decline as unsupported is declined",
			events.Request{Family: events.FamilyV4, Type: "DECLINE", Outcome: events.OutcomeUnsupported},
			leaseDeclined,
		},
		{
			"decline replied is not declined",
			events.Request{Family: events.FamilyV4, Type: "DECLINE", Outcome: events.OutcomeReplied},
			leaseNone,
		},
		{
			"inform carries no lease",
			events.Request{Family: events.FamilyV4, Type: "INFORM", ReplyType: "ACK", Outcome: events.OutcomeReplied},
			leaseNone,
		},
		{
			"an outcome other than replied says nothing",
			events.Request{Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER", Outcome: events.OutcomeDropped},
			leaseNone,
		},
		{
			"lower case types still match",
			events.Request{Family: events.FamilyV4, Type: "discover", ReplyType: "offer", Outcome: events.OutcomeReplied},
			leaseOffered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, leaseTransitionV4(tc.r))
			assert.Equal(t, tc.want, leaseTransition(tc.r))
		})
	}
}

// TestLeaseTransitionV6 pins every DHCPv6 rule from the README's "Where the
// lease states come from" table.
func TestLeaseTransitionV6(t *testing.T) {
	t.Parallel()

	addr := []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}

	tests := []struct {
		name string
		r    events.Request
		want leaseState
	}{
		{
			"solicit advertise issues a lease",
			events.Request{Family: events.FamilyV6, Type: "SOLICIT", ReplyType: "ADVERTISE", Outcome: events.OutcomeReplied},
			leaseOffered,
		},
		{
			"rapid commit solicit reply confirms",
			events.Request{Family: events.FamilyV6, Type: "SOLICIT", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseConfirmed,
		},
		{
			"request reply with addresses confirms",
			events.Request{Family: events.FamilyV6, Type: "REQUEST", ReplyType: "REPLY", Outcome: events.OutcomeReplied, Addresses: addr},
			leaseConfirmed,
		},
		{
			"renew reply with addresses confirms",
			events.Request{Family: events.FamilyV6, Type: "RENEW", ReplyType: "REPLY", Outcome: events.OutcomeReplied, Addresses: addr},
			leaseConfirmed,
		},
		{
			"rebind reply with addresses confirms",
			events.Request{Family: events.FamilyV6, Type: "REBIND", ReplyType: "REPLY", Outcome: events.OutcomeReplied, Addresses: addr},
			leaseConfirmed,
		},
		{
			"request reply with no addresses is refused",
			events.Request{Family: events.FamilyV6, Type: "REQUEST", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseRefused,
		},
		{
			"renew reply with no addresses is refused",
			events.Request{Family: events.FamilyV6, Type: "RENEW", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseRefused,
		},
		{
			"rebind reply with no addresses is refused",
			events.Request{Family: events.FamilyV6, Type: "REBIND", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseRefused,
		},
		{
			"confirm reply with addresses confirms",
			events.Request{Family: events.FamilyV6, Type: "CONFIRM", ReplyType: "REPLY", Outcome: events.OutcomeReplied, Addresses: addr},
			leaseConfirmed,
		},
		{
			"confirm needs addresses",
			events.Request{Family: events.FamilyV6, Type: "CONFIRM", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseNone,
		},
		{
			"release counts regardless of outcome",
			events.Request{Family: events.FamilyV6, Type: "RELEASE", Outcome: events.OutcomeDropped},
			leaseReleased,
		},
		{
			"information-request carries no lease",
			events.Request{Family: events.FamilyV6, Type: "INFORMATION-REQUEST", ReplyType: "REPLY", Outcome: events.OutcomeReplied},
			leaseNone,
		},
		{
			"an outcome other than replied says nothing",
			events.Request{Family: events.FamilyV6, Type: "REQUEST", ReplyType: "REPLY", Outcome: events.OutcomeDropped, Addresses: addr},
			leaseNone,
		},
		{
			"lower case types still match",
			events.Request{Family: events.FamilyV6, Type: "solicit", ReplyType: "advertise", Outcome: events.OutcomeReplied},
			leaseOffered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, leaseTransitionV6(tc.r))
			assert.Equal(t, tc.want, leaseTransition(tc.r))
		})
	}
}

// TestLeaseTransitionUnknownFamily pins that a family the table has no rule
// for says nothing about a lease.
func TestLeaseTransitionUnknownFamily(t *testing.T) {
	t.Parallel()

	assert.Equal(t, leaseNone, leaseTransition(events.Request{Family: events.Family(99)}))
}

// TestSolicitState pins the two answers a SOLICIT can get.
func TestSolicitState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		reply string
		want  leaseState
	}{
		{"advertise issues", "ADVERTISE", leaseOffered},
		{"rapid commit reply confirms", "REPLY", leaseConfirmed},
		{"anything else says nothing", "OTHER", leaseNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, solicitState(tc.reply))
		})
	}
}

// TestLeaseStateLabelAndTag pins the display word and colour for every
// lease state.
func TestLeaseStateLabelAndTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		s         leaseState
		wantLabel string
		wantTag   string
	}{
		{"none", leaseNone, "-", tagDim},
		{"offered", leaseOffered, "offered", tagWarn},
		{"confirmed", leaseConfirmed, "confirmed", tagGood},
		{"refused", leaseRefused, "refused", tagBad},
		{"released", leaseReleased, "released", tagDim},
		{"declined", leaseDeclined, "declined", tagBad},
		{"sentinel", leaseStateCount, "-", tagDim},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantLabel, tc.s.label())
			assert.Equal(t, tc.wantTag, tc.s.tag())
		})
	}
}

// TestLeaseTableUpdate pins how one update touches an entry: creation,
// re-ordering to the front, selective field replacement and the expiry
// rules.
func TestLeaseTableUpdate(t *testing.T) {
	t.Parallel()

	t.Run("creating and then touching orders most recently seen first", func(t *testing.T) {
		t.Parallel()

		tbl := newLeaseTable(10)
		a := events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime}
		b := events.Request{Family: events.FamilyV4, ClientID: "b", Time: baseTime.Add(time.Second)}

		tbl.update(a, leaseOffered)
		tbl.update(b, leaseOffered)

		rows := tbl.rows()
		require.Len(t, rows, 2)
		assert.Equal(t, "b", rows[0].client)
		assert.Equal(t, "a", rows[1].client)

		tbl.update(a, leaseConfirmed)
		rows = tbl.rows()
		assert.Equal(t, "a", rows[0].client)
		assert.Equal(t, "b", rows[1].client)
	})

	t.Run("hostname plugin and addresses are only replaced when carried", func(t *testing.T) {
		t.Parallel()

		tbl := newLeaseTable(10)
		full := events.Request{
			Family: events.FamilyV4, ClientID: "a", Time: baseTime,
			Hostname: "laptop", Plugin: "range",
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
		}
		tbl.update(full, leaseOffered)

		bare := events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime.Add(time.Second)}
		tbl.update(bare, leaseConfirmed)

		row := tbl.rows()[0]
		assert.Equal(t, "laptop", row.hostname)
		assert.Equal(t, "range", row.plugin)
		require.Len(t, row.addrs, 1)
	})

	t.Run("expiry is set from time plus lease time", func(t *testing.T) {
		t.Parallel()

		tbl := newLeaseTable(10)
		r := events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime, LeaseTime: time.Hour}
		tbl.update(r, leaseOffered)

		assert.True(t, tbl.rows()[0].expiry.Equal(baseTime.Add(time.Hour)))
	})

	t.Run("expiry is kept across an ack with no lease time", func(t *testing.T) {
		t.Parallel()

		tbl := newLeaseTable(10)
		tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime, LeaseTime: time.Hour}, leaseOffered)
		tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime.Add(time.Second)}, leaseConfirmed)

		assert.True(t, tbl.rows()[0].expiry.Equal(baseTime.Add(time.Hour)))
	})

	t.Run("expiry is cleared on release refuse and decline", func(t *testing.T) {
		t.Parallel()

		for _, state := range []leaseState{leaseReleased, leaseRefused, leaseDeclined} {
			tbl := newLeaseTable(10)
			tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime, LeaseTime: time.Hour}, leaseOffered)
			tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime.Add(time.Second)}, state)

			assert.True(t, tbl.rows()[0].expiry.IsZero())
		}
	})
}

// TestLeaseTableEviction pins that the least recently seen entry is dropped
// once the table is full.
func TestLeaseTableEviction(t *testing.T) {
	t.Parallel()

	tbl := newLeaseTable(2)
	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime}, leaseOffered)
	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "b", Time: baseTime.Add(time.Second)}, leaseOffered)
	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "c", Time: baseTime.Add(2 * time.Second)}, leaseOffered)

	rows := tbl.rows()
	require.Len(t, rows, 2)
	assert.Equal(t, "c", rows[0].client)
	assert.Equal(t, "b", rows[1].client)
}

// TestLeaseTableCounts pins that the per-state tally follows the table's
// entries, including through a touch that changes state.
func TestLeaseTableCounts(t *testing.T) {
	t.Parallel()

	tbl := newLeaseTable(10)
	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime}, leaseOffered)
	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "b", Time: baseTime}, leaseOffered)

	counts := tbl.counts()
	assert.Equal(t, 2, counts[leaseOffered])

	tbl.update(events.Request{Family: events.FamilyV4, ClientID: "a", Time: baseTime.Add(time.Second)}, leaseConfirmed)
	counts = tbl.counts()
	assert.Equal(t, 1, counts[leaseOffered])
	assert.Equal(t, 1, counts[leaseConfirmed])
}

// TestLeaseTableUnlinkPushFront pins the intrusive list operations at the
// head, middle and tail of the list.
func TestLeaseTableUnlinkPushFront(t *testing.T) {
	t.Parallel()

	build := func() (*leaseTable, *leaseEntry, *leaseEntry, *leaseEntry) {
		tbl := newLeaseTable(10)
		a := &leaseEntry{key: leaseKey{client: "a"}}
		b := &leaseEntry{key: leaseKey{client: "b"}}
		c := &leaseEntry{key: leaseKey{client: "c"}}
		tbl.pushFront(a)
		tbl.pushFront(b)
		tbl.pushFront(c)

		return tbl, a, b, c
	}

	t.Run("pushFront orders newest at the head", func(t *testing.T) {
		t.Parallel()

		tbl, a, _, c := build()
		assert.Same(t, c, tbl.head)
		assert.Same(t, a, tbl.tail)
		assert.Equal(t, []string{"c", "b", "a"}, listClients(tbl.head))
	})

	t.Run("unlink at the head", func(t *testing.T) {
		t.Parallel()

		tbl, a, b, c := build()
		tbl.unlink(c)
		assert.Same(t, b, tbl.head)
		assert.Same(t, a, tbl.tail)
		assert.Equal(t, []string{"b", "a"}, listClients(tbl.head))
	})

	t.Run("unlink in the middle", func(t *testing.T) {
		t.Parallel()

		tbl, a, b, c := build()
		tbl.unlink(b)
		assert.Same(t, c, tbl.head)
		assert.Same(t, a, tbl.tail)
		assert.Equal(t, []string{"c", "a"}, listClients(tbl.head))
	})

	t.Run("unlink at the tail", func(t *testing.T) {
		t.Parallel()

		tbl, _, b, c := build()
		tbl.unlink(tbl.tail)
		assert.Same(t, c, tbl.head)
		assert.Same(t, b, tbl.tail)
		assert.Equal(t, []string{"c", "b"}, listClients(tbl.head))
	})
}

// TestRecordLease pins the issued/confirmed totals and that an empty client
// identifier is ignored.
func TestRecordLease(t *testing.T) {
	t.Parallel()

	t.Run("issued and confirmed totals", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordLease(events.Request{
			Family: events.FamilyV4, ClientID: "a", Time: baseTime,
			Type: "DISCOVER", ReplyType: "OFFER", Outcome: events.OutcomeReplied,
		})
		m.recordLease(events.Request{
			Family: events.FamilyV4, ClientID: "a", Time: baseTime,
			Type: "REQUEST", ReplyType: "ACK", Outcome: events.OutcomeReplied,
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
		})

		assert.EqualValues(t, 1, m.tot.issued)
		assert.EqualValues(t, 1, m.tot.confirmed)
	})

	t.Run("an empty client identifier is ignored", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		m.recordLease(events.Request{
			Family: events.FamilyV4, Time: baseTime,
			Type: "DISCOVER", ReplyType: "OFFER", Outcome: events.OutcomeReplied,
		})

		assert.Zero(t, m.tot.issued)
		assert.Empty(t, m.leases.rows())
	})
}

// TestLeaseColumns pins the column layout at a floor width, a width where
// only the plugin column survives dropping, and a wide terminal.
func TestLeaseColumns(t *testing.T) {
	t.Parallel()

	t.Run("very narrow drops plugin lease and seen in that order", func(t *testing.T) {
		t.Parallel()

		c := leaseColumns(30)
		assert.Equal(t, leaseCols{client: 11, addr: 8, state: 9, lease: 0, seen: 0, plugin: 0}, c)
	})

	t.Run("a mid width drops only the plugin column", func(t *testing.T) {
		t.Parallel()

		c := leaseColumns(50)
		assert.Equal(t, leaseCols{client: 12, addr: 8, state: 9, lease: 8, seen: 9, plugin: 0}, c)
	})

	t.Run("a wide terminal grows the client and address columns", func(t *testing.T) {
		t.Parallel()

		c := leaseColumns(100)
		assert.Equal(t, leaseCols{client: 20, addr: 39, state: 9, lease: 8, seen: 9, plugin: 10}, c)
	})
}

// TestLeaseColsWidthAndGrow pins the width accounting and the grow helper.
func TestLeaseColsWidthAndGrow(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, leaseCols{}.width())
	assert.Equal(t, 9, leaseCols{client: 5, state: 3}.width())

	field := 5
	grow(&field, 10, 0)
	assert.Equal(t, 5, field, "no spare means no growth")

	field = 5
	grow(&field, 10, 3)
	assert.Equal(t, 8, field, "grows by the spare when under the ceiling")

	field = 10
	grow(&field, 10, 5)
	assert.Equal(t, 10, field, "never grows past the ceiling")
}

// TestLeaseLines pins the header row, the empty placeholder and one
// rendered row.
func TestLeaseLines(t *testing.T) {
	t.Parallel()

	t.Run("empty table shows the header and a placeholder", func(t *testing.T) {
		t.Parallel()

		lines := leaseLines(snapshot{now: baseTime}, 60)
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], "client")
		assert.Contains(t, lines[1], "no leases seen yet")
	})

	t.Run("the header row is line zero and rows follow", func(t *testing.T) {
		t.Parallel()

		snap := snapshot{now: baseTime, leases: []leaseRow{
			{family: events.FamilyV4, client: "ab:cd", state: leaseConfirmed, seen: baseTime},
		}}

		lines := leaseLines(snap, 60)
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], "client")
		assert.Contains(t, lines[1], "ab:cd")
	})
}

// TestWriteLease pins the row layout, including the hostname riding along
// the client cell and a dropped column being skipped.
func TestWriteLease(t *testing.T) {
	t.Parallel()

	cols := leaseCols{client: 30, addr: 20, state: 10, lease: 8, seen: 9, plugin: 10}

	withHost := writeLease(100, cols, leaseCells{
		client: "aa:bb:cc:dd:ee:ff", host: "laptop", addr: "10.0.0.5", state: "confirmed",
		lease: "59m", seen: "now", plugin: "range",
		clientTag: tagPlain, stateTag: tagGood, leaseTag: tagPlain,
	})
	assert.Contains(t, withHost, "laptop")
	assert.Contains(t, withHost, "confirmed")

	noHost := writeLease(100, cols, leaseCells{client: "aa:bb:cc:dd:ee:ff", state: "offered"})
	assert.NotContains(t, noHost, "laptop")

	narrowCols := leaseColumns(30)
	narrow := writeLease(30, narrowCols, leaseCells{
		client: "aa:bb:cc:dd:ee:ff", addr: "10.0.0.5", state: "offered",
		lease: "1h", seen: "now", plugin: "range",
	})
	assert.NotContains(t, narrow, "range", "the plugin column was dropped at this width")
}

// TestLeaseRowCells pins the field-by-field transformation from a lease row
// to its rendered cells.
func TestLeaseRowCells(t *testing.T) {
	t.Parallel()

	row := leaseRow{
		client: "aa:bb:cc:dd:ee:ff", hostname: "laptop",
		addrs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
		plugin: "range", state: leaseConfirmed,
		seen: baseTime.Add(-90 * time.Second), expiry: baseTime.Add(time.Hour),
	}

	cells := leaseRowCells(baseTime, row)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", cells.client)
	assert.Equal(t, "10.0.0.5", cells.addr)
	assert.Equal(t, "confirmed", cells.state)
	assert.Equal(t, "1h00m", cells.lease)
	assert.Equal(t, "1m30s ago", cells.seen)
	assert.Equal(t, "range", cells.plugin)
	assert.Equal(t, tagGood, cells.stateTag)
	assert.Equal(t, tagPlain, cells.leaseTag)
}

// TestLeaseTimeTag pins that an expired or unknown lease dims, while a
// counting-down lease stays plain.
func TestLeaseTimeTag(t *testing.T) {
	t.Parallel()

	assert.Equal(t, tagDim, leaseTimeTag(baseTime, leaseRow{}))
	assert.Equal(t, tagDim, leaseTimeTag(baseTime, leaseRow{expiry: baseTime.Add(-time.Second)}))
	assert.Equal(t, tagPlain, leaseTimeTag(baseTime, leaseRow{expiry: baseTime.Add(time.Second)}))
}

// TestLeaseTitle pins the pane title's live counters.
func TestLeaseTitle(t *testing.T) {
	t.Parallel()

	var counts [leaseStateCount]int
	counts[leaseOffered] = 3
	counts[leaseConfirmed] = 7

	title := leaseTitle(snapshot{leaseCounts: counts})
	assert.Equal(t, " leases (3 offered, 7 confirmed) ", title)
}

// ---------------------------------------------------------------------------
// traffic.go
// ---------------------------------------------------------------------------

// TestFamilyShort pins the two character family marker.
func TestFamilyShort(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "v4", familyShort(events.FamilyV4))
	assert.Equal(t, "v6", familyShort(events.FamilyV6))
	assert.Equal(t, "v?", familyShort(events.Family(99)))
}

// TestOutcomeWord pins the reply column's word and colour for every
// outcome, including a reply type outside the graded set.
func TestOutcomeWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		r        events.Request
		wantTag  string
		wantWord string
	}{
		{"a graded reply type", events.Request{Outcome: events.OutcomeReplied, ReplyType: "OFFER"}, tagGood, "OFFER"},
		{"a nak is a warning", events.Request{Outcome: events.OutcomeReplied, ReplyType: "NAK"}, tagWarn, "NAK"},
		{"a reply type outside replyTags", events.Request{Outcome: events.OutcomeReplied, ReplyType: "WEIRD"}, tagPlain, "WEIRD"},
		{"dropped", events.Request{Outcome: events.OutcomeDropped}, tagWarn, "drop"},
		{"parse error", events.Request{Outcome: events.OutcomeParseError}, tagBad, "parse"},
		{"unsupported", events.Request{Outcome: events.OutcomeUnsupported}, tagBad, "unsup"},
		{"send error", events.Request{Outcome: events.OutcomeSendError}, tagBad, "send"},
		{"an unknown outcome", events.Request{Outcome: events.Outcome(99)}, tagDim, "?"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tag, word := outcomeWord(tc.r)
			assert.Equal(t, tc.wantTag, tag)
			assert.Equal(t, tc.wantWord, word)
		})
	}
}

// TestTrafficTitle pins the paused marker in the pane title.
func TestTrafficTitle(t *testing.T) {
	t.Parallel()

	assert.Equal(t, " traffic (last 500) ", trafficTitle(snapshot{history: 500}))
	assert.Equal(t, " traffic (last 500, paused) ", trafficTitle(snapshot{history: 500, paused: true}))
}

// TestTrafficColumns pins the layout at a narrow width, where interface and
// plugin have already been dropped, and at a wide terminal where every
// column survives and the client and address columns grow.
func TestTrafficColumns(t *testing.T) {
	t.Parallel()

	t.Run("narrow drops path duration interface and plugin, then the client and address floor", func(t *testing.T) {
		t.Parallel()

		c := trafficColumns(30)
		assert.Equal(t, trafficCols{time: 8, fam: 2, iface: 0, typ: 9, reply: 9, client: 10, addr: 8, plugin: 0, path: 0, dur: 0}, c)
	})

	t.Run("a mid width keeps the short timestamp and the client floor", func(t *testing.T) {
		t.Parallel()

		c := trafficColumns(60)
		assert.Equal(t, trafficCols{time: 8, fam: 2, iface: 0, typ: 9, reply: 9, client: 17, addr: 8, plugin: 0, path: 0, dur: 0}, c)
	})

	t.Run("a wide terminal keeps every column and spends the rest on the wire data", func(t *testing.T) {
		t.Parallel()

		c := trafficColumns(120)
		assert.Equal(t, trafficCols{
			time: trafficTimeW, fam: trafficFamW, iface: trafficIfaceW, typ: trafficTypeW,
			reply: trafficReplyW, client: trafficWideClient, addr: 20,
			plugin: trafficPluginW, path: trafficPathW, dur: trafficDurW,
		}, c)
		assert.Equal(t, 120, c.width())
	})
}

// TestTrafficColsWidthAndShrink pins the width accounting and the shrink
// helper.
func TestTrafficColsWidthAndShrink(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 1, trafficCols{}.width(), "the arrow between request and reply always costs one column")
	assert.Equal(t, 7, trafficCols{time: 3, client: 1}.width(), "two data columns plus the arrow plus two gaps")

	field := 15
	shrink(&field, 8, 0)
	assert.Equal(t, 15, field, "nothing to shed means no shrink")

	field = 15
	shrink(&field, 8, 3)
	assert.Equal(t, 12, field, "shrinks by the amount over")

	field = 15
	shrink(&field, 8, 99)
	assert.Equal(t, 8, field, "never shrinks past the floor")
}

// TestTrafficLines pins the empty ring placeholder and the row count for a
// populated ring.
func TestTrafficLines(t *testing.T) {
	t.Parallel()

	lines := trafficLines(snapshot{}, 80)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "waiting for the first request")

	snap := snapshot{traffic: []events.Request{
		{Time: baseTime, Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER", Outcome: events.OutcomeReplied},
		{Time: baseTime, Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK", Outcome: events.OutcomeReplied},
	}}
	lines = trafficLines(snap, 80)
	assert.Len(t, lines, 2)
}

// TestTrafficLine pins one rendered request row: a normal reply, a client
// id too long for its column, a parse error with no client, and an error
// row that does carry a client.
func TestTrafficLine(t *testing.T) {
	t.Parallel()

	t.Run("a normal reply shows client hostname and address", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Interface: "eth0", Type: "DISCOVER",
			ReplyType: "OFFER", ClientID: "ab:cd", Hostname: "laptop",
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
			Outcome:   events.OutcomeReplied, Path: events.PathLayer2, Duration: 400 * time.Microsecond,
		}, 150)

		assert.Contains(t, line, "DISCOVER")
		assert.Contains(t, line, "OFFER")
		assert.Contains(t, line, "ab:cd")
		assert.Contains(t, line, "laptop")
		assert.Contains(t, line, "10.0.0.5")
		assert.Contains(t, line, "layer2", "a wide enough pane keeps the reply path column")
		assert.Contains(t, line, "400µs", "a wide enough pane keeps the duration column")
	})

	t.Run("a dropped request shows the drop word", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Type: "DISCOVER", Outcome: events.OutcomeDropped,
		}, 100)
		assert.Contains(t, line, "drop")
	})

	t.Run("a client id too long for its column renders end-anchored", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK",
			ClientID: "aa:bb:cc:dd:ee:ff", Outcome: events.OutcomeReplied,
		}, 45)

		assert.NotContains(t, line, "aa:bb:cc:dd:e…", "the old front-anchored truncation is gone")
		assert.Contains(t, line, "…")
		assert.Contains(t, line, "ee:ff", "the end of the identifier is what survives")
	})

	t.Run("a parse error with no client puts the error right after the reply column", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Outcome: events.OutcomeParseError, Error: "short packet",
		}, 100)

		assert.Contains(t, line, "parse")
		assert.Contains(t, line, "short packet")

		reply := strings.Index(line, "parse")
		errIdx := strings.Index(line, "short packet")
		assert.Less(t, reply, errIdx)
	})

	t.Run("an error row with a client still shows the error", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Type: "REQUEST", ClientID: "aa:bb:cc:dd:ee:ff",
			Outcome: events.OutcomeSendError, Error: "write: broken pipe",
		}, 150)

		assert.Contains(t, line, "ee:ff")
		assert.Contains(t, line, "write: broken pipe")
	})

	t.Run("a hostname appears after the client id", func(t *testing.T) {
		t.Parallel()

		line := trafficLine(events.Request{
			Time: baseTime, Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK",
			ClientID: "ab:cd", Hostname: "printer", Outcome: events.OutcomeReplied,
		}, 100)

		client := strings.Index(line, "ab:cd")
		host := strings.Index(line, "printer")
		require.GreaterOrEqual(t, client, 0)
		require.GreaterOrEqual(t, host, 0)
		assert.Less(t, client, host)
	})
}

// ---------------------------------------------------------------------------
// plugins.go
// ---------------------------------------------------------------------------

// TestRedactArg pins every redaction rule for a single plugin argument.
func TestRedactArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		want string
	}{
		{"an env reference passes through", "env:REDIS_PASSWORD", "env:REDIS_PASSWORD"},
		{"a long hex string is redacted", strings.Repeat("a", 32), "***"},
		{"a shorter hex string is left alone", strings.Repeat("a", 31), strings.Repeat("a", 31)},
		{"a url with user and password redacts the password", "redis://coredhcp:hunter2@10.0.0.9:6379", "redis://coredhcp:***@10.0.0.9:6379"},
		{"a url with a user and no password is left alone", "redis://user@10.0.0.9:6379", "redis://user@10.0.0.9:6379"},
		{"a url with no userinfo at all is left alone", "redis://10.0.0.9:6379", "redis://10.0.0.9:6379"},
		{"a string with no scheme is left alone", "leases.txt", "leases.txt"},
		{"an at sign in a path is not userinfo", "https://example.com/user@name", "https://example.com/user@name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, redactArg(tc.a))
		})
	}
}

// TestRedactArgs pins that redactArgs joins its redacted arguments with a
// space and returns the empty string for none.
func TestRedactArgs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", redactArgs(nil))
	assert.Equal(t, "deny /etc/coredhcp/deny.txt", redactArgs([]string{"deny", "/etc/coredhcp/deny.txt"}))
}

// TestTaggedWidth pins the rune-counted width of a run of tagged pieces.
func TestTaggedWidth(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, taggedWidth(nil))
	assert.Equal(t, 5, taggedWidth([]tagged{{tagDim, "×3"}, {tagGood, "✓12"}}))
}

// TestChainCounts pins the tally column for a link with no traffic, only
// replies, only drops, and both.
func TestChainCounts(t *testing.T) {
	t.Parallel()

	t.Run("no traffic shows only the reached count", func(t *testing.T) {
		t.Parallel()

		parts := chainCounts(chainLink{reached: 5})
		require.Len(t, parts, 1)
		assert.Equal(t, "×5", parts[0].text)
	})

	t.Run("replied only", func(t *testing.T) {
		t.Parallel()

		parts := chainCounts(chainLink{reached: 5, replied: 5})
		assert.Equal(t, "✓5", parts[len(parts)-1].text)
	})

	t.Run("dropped only", func(t *testing.T) {
		t.Parallel()

		parts := chainCounts(chainLink{reached: 5, dropped: 2})
		assert.Equal(t, "✗2", parts[len(parts)-1].text)
	})

	t.Run("both replied and dropped", func(t *testing.T) {
		t.Parallel()

		parts := chainCounts(chainLink{reached: 5, replied: 3, dropped: 2})
		require.Len(t, parts, 5)
		assert.Equal(t, "✓3", parts[2].text)
		assert.Equal(t, "✗2", parts[4].text)
	})
}

// TestPluginLines pins the per-family sections: an unconfigured family and
// one with a chain.
func TestPluginLines(t *testing.T) {
	t.Parallel()

	snap := snapshot{
		listeners: []events.Listener{{Family: events.FamilyV4, Address: "0.0.0.0:67"}},
		chains: map[events.Family][]chainLink{
			events.FamilyV4: {{name: "range", reached: 4, replied: 4}},
		},
	}

	lines := pluginLines(snap, 60)
	joined := strings.Join(lines, "\n")

	assert.Contains(t, joined, "DHCPv4")
	assert.Contains(t, joined, "range")
	assert.Contains(t, joined, "not configured", "DHCPv6 has no chain in this snapshot")
}

// TestFamilyHeader pins the listener summary next to the family name, and
// the "no listener" fallback.
func TestFamilyHeader(t *testing.T) {
	t.Parallel()

	withListener := familyHeader(snapshot{listeners: []events.Listener{
		{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"},
	}}, events.FamilyV4, 60)
	assert.Contains(t, withListener, "0.0.0.0:67")
	assert.Contains(t, withListener, "eth0")

	noListener := familyHeader(snapshot{}, events.FamilyV6, 60)
	assert.Contains(t, noListener, "no listener")
}

// TestListenerText pins how a family's bound addresses are joined,
// including the interface suffix.
func TestListenerText(t *testing.T) {
	t.Parallel()

	listeners := []events.Listener{
		{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"},
		{Family: events.FamilyV4, Address: "127.0.0.1:67"},
		{Family: events.FamilyV6, Address: "[::]:547"},
	}

	assert.Equal(t, "0.0.0.0:67 (eth0), 127.0.0.1:67", listenerText(listeners, events.FamilyV4))
	assert.Equal(t, "", listenerText(listeners, events.Family(99)))
}

// TestChainLine pins a plugin's row, with the tallies pinned to the right
// edge, and behaviour at a narrow width.
func TestChainLine(t *testing.T) {
	t.Parallel()

	line := chainLine(1, chainLink{name: "range", args: []string{"10.0.0.5", "10.0.0.50"}, reached: 4, replied: 4}, 60)
	assert.Contains(t, line, "range")
	assert.Contains(t, line, "10.0.0.5")
	assert.Contains(t, line, "×4")
	assert.Contains(t, line, "✓4")

	narrow := chainLine(2, chainLink{name: "macfilter", reached: 1, dropped: 1}, 12)
	assert.Contains(t, narrow, "✗1", "the tally column survives even when the name has to be clipped")
}

// TestClipTo pins the plain-string wrapper around clip.
func TestClipTo(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ab…", clipTo("abcdef", 3))
	assert.Equal(t, "ab", clipTo("ab", 5))
}

// ---------------------------------------------------------------------------
// counters.go
// ---------------------------------------------------------------------------

// TestCounterLines pins a family with no requests and one with counters.
func TestCounterLines(t *testing.T) {
	t.Parallel()

	snap := snapshot{counts: map[events.Family]familyCounters{
		events.FamilyV4: {total: 2, in: map[string]uint64{"DISCOVER": 2}, out: map[string]uint64{"OFFER": 2}},
	}}

	lines := counterLines(snap, 60)
	joined := strings.Join(lines, "\n")

	assert.Contains(t, joined, "no requests", "DHCPv6 has no counters in this snapshot")
	assert.Contains(t, joined, "DISCOVER")
}

// TestCounterHeader pins the family name and request total.
func TestCounterHeader(t *testing.T) {
	t.Parallel()

	line := counterHeader(events.FamilyV4, 42, 60)
	assert.Contains(t, line, "DHCPv4")
	assert.Contains(t, line, "42 req")
}

// TestTypeLine pins the label and the busiest types on one row.
func TestTypeLine(t *testing.T) {
	t.Parallel()

	line := typeLine("in ", map[string]uint64{"DISCOVER": 5, "REQUEST": 3}, 60)
	assert.Contains(t, line, "in")
	assert.Contains(t, line, "DISCOVER")
	assert.Contains(t, line, "REQUEST")
}

// TestTopTypes pins the ordering by count then name, and the n cap.
func TestTopTypes(t *testing.T) {
	t.Parallel()

	counts := map[string]uint64{"B": 5, "A": 5, "C": 9, "D": 1}
	top := topTypes(counts, 3)

	require.Len(t, top, 3)
	assert.Equal(t, namedCount{"C", 9}, top[0])
	assert.Equal(t, namedCount{"A", 5}, top[1], "equal counts break ties by name")
	assert.Equal(t, namedCount{"B", 5}, top[2])
}

// TestProblemLine pins that a zero count stays dim while a non-zero count
// takes its grading colour.
func TestProblemLine(t *testing.T) {
	t.Parallel()

	healthy := problemLine(familyCounters{}, 60)
	assert.NotContains(t, healthy, "[red]")

	unhealthy := problemLine(familyCounters{parseErrs: 3}, 60)
	assert.Contains(t, unhealthy, "parse")
	assert.Contains(t, unhealthy, "3")
}

// TestPathLine pins the reply-path breakdown, and the "-" fallback when no
// path was used.
func TestPathLine(t *testing.T) {
	t.Parallel()

	assert.Contains(t, pathLine(familyCounters{}, 60), "-")

	var c familyCounters
	c.paths[events.PathUnicast] = 4

	line := pathLine(c, 60)
	assert.Contains(t, line, "unicast")
	assert.Contains(t, line, "4")
}

// ---------------------------------------------------------------------------
// rate.go
// ---------------------------------------------------------------------------

// TestRateLines pins that the rate pane renders three rows: requests,
// errors and chain latency.
func TestRateLines(t *testing.T) {
	t.Parallel()

	snap := snapshot{
		reqRate: []uint32{1, 2, 3},
		errRate: []uint32{0, 1, 0},
		traffic: []events.Request{{Duration: 10 * time.Millisecond}},
	}

	lines := rateLines(snap, 60)
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "req")
	assert.Contains(t, lines[1], "err")
	assert.Contains(t, lines[2], "chain")
}

// TestErrLabel pins the error history's summary word.
func TestErrLabel(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "none in 60 s", errLabel(0))
	assert.Equal(t, "3 in 60 s", errLabel(3))
}

// TestSparkRow pins the label, sparkline and trailing scale, including the
// error row's colour when it has something to show.
func TestSparkRow(t *testing.T) {
	t.Parallel()

	req := sparkRow("req", []uint32{1, 2, 3}, 3, "max 3/s", 60)
	assert.Contains(t, req, "req")
	assert.Contains(t, req, "max 3/s")

	errRow := sparkRow("err", []uint32{1}, 1, "1 in 60 s", 60)
	assert.Contains(t, errRow, "[red]")
}

// TestChainLatencyLine pins the "no timings yet" placeholder and a line
// with a median and a maximum.
func TestChainLatencyLine(t *testing.T) {
	t.Parallel()

	assert.Contains(t, chainLatencyLine(nil, 60), "no timings yet")

	line := chainLatencyLine([]events.Request{{Duration: 10 * time.Millisecond}, {Duration: 20 * time.Millisecond}}, 60)
	assert.Contains(t, line, "p50")
	assert.Contains(t, line, "max")
}

// TestChainLatency pins the median and maximum computed over the traffic
// still in the ring, ignoring entries with no duration.
func TestChainLatency(t *testing.T) {
	t.Parallel()

	_, _, ok := chainLatency(nil)
	assert.False(t, ok)

	median, top, ok := chainLatency([]events.Request{
		{Duration: 0},
		{Duration: 10 * time.Millisecond},
		{Duration: 30 * time.Millisecond},
		{Duration: 20 * time.Millisecond},
	})
	require.True(t, ok)
	assert.Equal(t, 20*time.Millisecond, median)
	assert.Equal(t, 30*time.Millisecond, top)
}

// TestLatencyTag pins the slow-chain grading threshold.
func TestLatencyTag(t *testing.T) {
	t.Parallel()

	assert.Equal(t, tagPlain, latencyTag(slowChain-time.Millisecond))
	assert.Equal(t, tagWarn, latencyTag(slowChain))
}

// ---------------------------------------------------------------------------
// status.go
// ---------------------------------------------------------------------------

// TestHeaderLine pins that the header row carries the running totals.
func TestHeaderLine(t *testing.T) {
	t.Parallel()

	snap := snapshot{
		now: baseTime, uptime: time.Hour, version: "v0.2.0",
		listeners: []events.Listener{{Family: events.FamilyV4}},
		reqRate:   []uint32{1, 2},
		tot:       totals{requests: 10, issued: 4, confirmed: 3, dropped: 1, errors: 2},
	}

	line := headerLine(snap, 100)
	assert.Contains(t, line, "coredhcp")
	assert.Contains(t, line, "v0.2.0")
	assert.Contains(t, line, "listeners=1")
	assert.Contains(t, line, "req=10")
	assert.Contains(t, line, "issued=4")
	assert.Contains(t, line, "confirmed=3")
	assert.Contains(t, line, "dropped=1")
	assert.Contains(t, line, "errors=2")
}

// TestCountTag pins that a counter only takes its colour once it has
// something to say.
func TestCountTag(t *testing.T) {
	t.Parallel()

	assert.Equal(t, tagPlain, countTag(0, tagBad))
	assert.Equal(t, tagBad, countTag(1, tagBad))
}

// TestRecentRate pins the mean over the trailing window: empty, shorter
// than the window, and a full window.
func TestRecentRate(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "0.0", recentRate(nil))
	assert.Equal(t, "2.0", recentRate([]uint32{1, 2, 3}))

	series := make([]uint32, 15)
	for i := 5; i < 15; i++ {
		series[i] = uint32(i)
	}

	assert.Equal(t, "9.5", recentRate(series))
}

// TestGrade pins every branch of the server's health grading, in the order
// it is checked.
func TestGrade(t *testing.T) {
	t.Parallel()

	listener := []events.Listener{{Family: events.FamilyV4}}

	t.Run("no listeners is the worst case", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{now: baseTime})
		assert.Equal(t, "FAILING", h.label)
		assert.Contains(t, h.note, "no listeners bound")
	})

	t.Run("a send error inside the window fails", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{now: baseTime, listeners: listener, tot: totals{lastSendErr: baseTime.Add(-time.Second)}})
		assert.Equal(t, "FAILING", h.label)
		assert.Contains(t, h.note, "failed to send")
	})

	t.Run("a soft error inside the window degrades", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{now: baseTime, listeners: listener, tot: totals{lastSoftErr: baseTime.Add(-time.Second)}})
		assert.Equal(t, "DEGRADED", h.label)
		assert.Contains(t, h.note, "could not use")
	})

	t.Run("no requests yet is idle", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{now: baseTime, listeners: listener})
		assert.Equal(t, "IDLE", h.label)
	})

	t.Run("no errors in the window is healthy", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{
			now: baseTime, listeners: listener,
			tot: totals{requests: 5, lastRequest: baseTime.Add(-time.Second)},
		})
		assert.Equal(t, "HEALTHY", h.label)
		assert.Contains(t, h.note, "last request")
	})

	t.Run("an error outside the window no longer counts", func(t *testing.T) {
		t.Parallel()

		h := grade(snapshot{
			now: baseTime, listeners: listener,
			tot: totals{
				requests: 5, lastRequest: baseTime.Add(-time.Second),
				lastSoftErr: baseTime.Add(-2 * errorWindow), lastSendErr: baseTime.Add(-2 * errorWindow),
			},
		})
		assert.Equal(t, "HEALTHY", h.label)
	})
}

// TestWithin pins the error-grading window's boundary.
func TestWithin(t *testing.T) {
	t.Parallel()

	assert.False(t, within(baseTime, time.Time{}))
	assert.True(t, within(baseTime, baseTime.Add(-time.Second)))
	assert.False(t, within(baseTime, baseTime.Add(-errorWindow)))
}

// TestListenerNote pins the singular and plural listener counts.
func TestListenerNote(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "1 listener", listenerNote(snapshot{listeners: []events.Listener{{}}}))
	assert.Equal(t, "2 listeners", listenerNote(snapshot{listeners: []events.Listener{{}, {}}}))
}

// TestRequestNote pins the last-request note, including the never-seen
// case.
func TestRequestNote(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ", no requests yet", requestNote(snapshot{now: baseTime}))
	assert.Contains(t, requestNote(snapshot{now: baseTime, tot: totals{lastRequest: baseTime.Add(-time.Second)}}), "last request")
}

// TestStatusLine pins that the status row carries the graded label and
// note.
func TestStatusLine(t *testing.T) {
	t.Parallel()

	line := statusLine(snapshot{now: baseTime}, 80)
	assert.Contains(t, line, "status:")
	assert.Contains(t, line, "FAILING")
}

// TestFooterLine pins the key hints and the paused marker.
func TestFooterLine(t *testing.T) {
	t.Parallel()

	plain := footerLine(snapshot{}, 80)
	assert.Contains(t, plain, "quit")
	assert.NotContains(t, plain, "PAUSED")

	paused := footerLine(snapshot{paused: true}, 80)
	assert.Contains(t, paused, "PAUSED")
}

// TestHelpLinesAndHelpText pins the overlay's static content and that
// helpText joins it with newlines.
func TestHelpLinesAndHelpText(t *testing.T) {
	t.Parallel()

	lines := helpLines()
	assert.NotEmpty(t, lines)
	assert.Equal(t, strings.Join(lines, "\n"), helpText())

	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, "quit")
	assert.Contains(t, joined, "lease database")
}

// ---------------------------------------------------------------------------
// log.go
// ---------------------------------------------------------------------------

// TestLogWriterWrite pins how bytes are split into whole log lines,
// including a line held across writes, a CRLF ending, and a line capped at
// maxLogLineLen without letting the internal buffer grow past it.
func TestLogWriterWrite(t *testing.T) {
	t.Parallel()

	t.Run("a whole line", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		n, err := w.Write([]byte("hello\n"))
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		require.Len(t, m.logs.items(), 1)
		assert.Equal(t, "hello", m.logs.items()[0].raw)
	})

	t.Run("several lines in one write", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		_, err := w.Write([]byte("a\nb\nc\n"))
		require.NoError(t, err)

		entries := m.logs.items()
		require.Len(t, entries, 3)
		assert.Equal(t, []string{"a", "b", "c"}, []string{entries[0].raw, entries[1].raw, entries[2].raw})
	})

	t.Run("a line split across writes", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		_, err := w.Write([]byte("hel"))
		require.NoError(t, err)
		assert.Empty(t, m.logs.items())

		_, err = w.Write([]byte("lo\n"))
		require.NoError(t, err)

		require.Len(t, m.logs.items(), 1)
		assert.Equal(t, "hello", m.logs.items()[0].raw)
	})

	t.Run("a crlf line ending drops the carriage return", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		_, err := w.Write([]byte("hi\r\n"))
		require.NoError(t, err)

		require.Len(t, m.logs.items(), 1)
		assert.Equal(t, "hi", m.logs.items()[0].raw)
	})

	t.Run("a line longer than the cap is capped without growing the buffer", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		chunk := strings.Repeat("x", maxLogLineLen/2+50)

		_, err := w.Write([]byte(chunk))
		require.NoError(t, err)
		assert.LessOrEqual(t, len(w.buf), maxLogLineLen)

		_, err = w.Write([]byte(chunk))
		require.NoError(t, err)
		assert.LessOrEqual(t, len(w.buf), maxLogLineLen)

		_, err = w.Write([]byte("\n"))
		require.NoError(t, err)

		require.Len(t, m.logs.items(), 1)
		assert.LessOrEqual(t, len([]rune(m.logs.items()[0].raw)), maxLogLineLen)
	})

	t.Run("the returned length is always len(p) and the error is always nil", func(t *testing.T) {
		t.Parallel()

		m := newModel(baseTime, "v", 10, 10, 10)
		w := &logWriter{m: m, now: func() time.Time { return baseTime }}

		for _, p := range [][]byte{nil, []byte(""), []byte("x"), []byte("a\nb\nc")} {
			n, err := w.Write(p)
			require.NoError(t, err)
			assert.Equal(t, len(p), n)
		}
	})
}

// TestParseLogLine pins the slog text-handler parser against a full line,
// quoting rules, extra attributes, and the unparsed fallbacks.
func TestParseLogLine(t *testing.T) {
	t.Parallel()

	t.Run("a full slog line", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`time=2026-08-19T12:09:32.986+02:00 level=INFO msg="Listen [::]:547" prefix=server`)
		require.True(t, f.parsed)
		assert.Equal(t, "INFO", f.level)
		assert.Equal(t, "server", f.prefix)
		assert.Equal(t, "Listen [::]:547", f.msg)
		assert.Empty(t, f.extra)
		assert.False(t, f.at.IsZero())
	})

	t.Run("quoted values with escapes", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`level=INFO msg="he said \"hi\""`)
		require.True(t, f.parsed)
		assert.Equal(t, `he said "hi"`, f.msg)
	})

	t.Run("a value at the end of the line", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`level=INFO msg=hello`)
		require.True(t, f.parsed)
		assert.Equal(t, "hello", f.msg)
	})

	t.Run("extra attributes are collected", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`level=WARN msg="reloaded" leases=42 foo=bar`)
		require.True(t, f.parsed)
		assert.Equal(t, "leases=42 foo=bar", f.extra)
	})

	t.Run("an unparseable line is reported as not parsed", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine("this is not key value pairs")
		assert.False(t, f.parsed)
	})

	t.Run("a line with no msg is reported as not parsed", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`time=2026-08-19T12:09:32.986+02:00 level=INFO prefix=server`)
		assert.False(t, f.parsed)
	})

	t.Run("a bad timestamp falls back to zero", func(t *testing.T) {
		t.Parallel()

		f := parseLogLine(`time=not-a-time level=INFO msg="x"`)
		assert.True(t, f.at.IsZero())
	})
}

// TestScanPair pins reading one key=value pair off the front of a line.
func TestScanPair(t *testing.T) {
	t.Parallel()

	key, value, rest, ok := scanPair(`msg="hi there" next=1`)
	require.True(t, ok)
	assert.Equal(t, "msg", key)
	assert.Equal(t, "hi there", value)
	assert.Equal(t, " next=1", rest, "the caller trims leading space before the next scanPair call")

	_, _, _, ok = scanPair("badtoken next=val")
	assert.False(t, ok)

	_, _, _, ok = scanPair("=novalue")
	assert.False(t, ok)
}

// TestScanValue pins the unquoted, quoted, unterminated and invalid quoted
// value readers.
func TestScanValue(t *testing.T) {
	t.Parallel()

	v, n := scanValue("abc def")
	assert.Equal(t, "abc", v)
	assert.Equal(t, 3, n)

	v, n = scanValue(`"quoted value" rest`)
	assert.Equal(t, "quoted value", v)
	assert.Equal(t, 14, n)

	v, n = scanValue(`"unterminated`)
	assert.Equal(t, `"unterminated`, v)
	assert.Equal(t, 13, n)

	v, n = scanValue(`"\q"`)
	assert.Equal(t, `"\q"`, v)
	assert.Equal(t, 4, n)
}

// TestParseLogTime pins the handler's timestamp format and the zero-time
// fallback.
func TestParseLogTime(t *testing.T) {
	t.Parallel()

	got := parseLogTime("2026-08-19T12:09:32.986+02:00")
	assert.False(t, got.IsZero())

	assert.True(t, parseLogTime("not a time").IsZero())
}

// TestLevelTag pins the colour for every log level, including one the
// server does not use.
func TestLevelTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level string
		want  string
	}{
		{"INFO", tagGood},
		{"WARN", tagWarn},
		{"WARNING", tagWarn},
		{"ERROR", tagBad},
		{"FATAL", tagBad},
		{"PANIC", tagBad},
		{"DEBUG", tagDim},
		{"TRACE", tagDim},
		{"WEIRD", tagPlain},
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, levelTag(tc.level))
		})
	}
}

// TestLogLines pins the empty-ring placeholder.
func TestLogLines(t *testing.T) {
	t.Parallel()

	lines := logLines(snapshot{}, 80)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "no log lines yet")
}

// TestLogLine pins a parsed line, an unparsed line shown raw, a line with
// no timestamp falling back to arrival time, and extras riding along.
func TestLogLine(t *testing.T) {
	t.Parallel()

	t.Run("a parsed line renders its fields", func(t *testing.T) {
		t.Parallel()

		e := logEntry{at: baseTime, raw: `time=2026-08-19T12:09:32.986+02:00 level=INFO msg="hi" prefix=server extra=1`}
		line := logLine(e, 80)
		assert.Contains(t, line, "INFO")
		assert.Contains(t, line, "server")
		assert.Contains(t, line, "hi")
		assert.Contains(t, line, "extra=1")
	})

	t.Run("an unparsed line is shown raw", func(t *testing.T) {
		t.Parallel()

		e := logEntry{at: baseTime, raw: "not a log line at all"}
		line := logLine(e, 80)
		assert.Contains(t, line, "not a log line at all")
	})

	t.Run("no timestamp in the line falls back to arrival time", func(t *testing.T) {
		t.Parallel()

		e := logEntry{at: baseTime, raw: `level=INFO msg="hi"`}
		line := logLine(e, 80)
		assert.Contains(t, line, baseTime.Format("15:04:05"))
	})
}

// ---------------------------------------------------------------------------
// ui.go (construction only; Run/Stop and the draw loop belong to the
// external test's screen-driven coverage)
// ---------------------------------------------------------------------------

// TestNewFallsBackOnBadOptions pins that New repairs every option value it
// cannot work with: a nil clock, a non-positive refresh, and non-positive
// ring sizes all fall back to their defaults instead of sticking.
func TestNewFallsBackOnBadOptions(t *testing.T) {
	t.Parallel()

	u := New(WithClock(nil), WithRefresh(-1), WithHistory(0), WithMaxLeases(-1), WithLogLines(0))

	assert.NotNil(t, u.now)
	assert.NotPanics(t, func() { u.now() })
	assert.Equal(t, defaultRefresh, u.refresh)
	assert.Equal(t, defaultHistory, u.history)
	assert.Equal(t, defaultMaxLeases, u.maxLeases)
	assert.Equal(t, defaultLogLines, u.logLines)
}

// watchTimeout bounds how long the watch tests wait for the watcher goroutine
// to close the channel it returns.
const watchTimeout = 2 * time.Second

// TestWaitStop pins which of the three ways a run ends waitStop reports as a
// stop request. Every case leaves exactly one channel ready, so the select
// has only one arm it can take.
func TestWaitStop(t *testing.T) {
	t.Parallel()

	closed := func() chan struct{} {
		ch := make(chan struct{})
		close(ch)

		return ch
	}

	t.Run("a cancelled context asks for a stop", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		assert.True(t, waitStop(ctx, make(chan struct{}), make(chan struct{})))
	})

	t.Run("Stop asks for a stop", func(t *testing.T) {
		t.Parallel()

		assert.True(t, waitStop(context.Background(), closed(), make(chan struct{})))
	})

	t.Run("a run that already ended leaves nothing to stop", func(t *testing.T) {
		t.Parallel()

		assert.False(t, waitStop(context.Background(), make(chan struct{}), closed()))
	})
}

// TestUIWatchReturnsWhenRunAlreadyEnded pins that the watcher gives up
// without touching the application when the run ended before anything asked
// it to stop. It is called directly against channels the test controls: no
// screen, no Run, and app.Stop is never reached, so an application that was
// never run, a zero wait group and a no-op cancel are all safe to pass.
func TestUIWatchReturnsWhenRunAlreadyEnded(t *testing.T) {
	t.Parallel()

	u := New(WithClock(func() time.Time { return baseTime }))

	var draws sync.WaitGroup

	runDone := make(chan struct{})
	close(runDone)

	done := u.watch(context.Background(), tview.NewApplication(), func() {}, &draws, make(chan struct{}), runDone)

	select {
	case <-done:
	case <-time.After(watchTimeout):
		t.Fatal("watch did not return once the run had already ended")
	}
}

// ---------------------------------------------------------------------------
// keys.go
// ---------------------------------------------------------------------------

// newKeyUI builds a UI with a fixed clock for the key-handling tests. No
// screen and no Run are involved: handleKey is called directly.
func newKeyUI(t *testing.T, at time.Time) *UI {
	t.Helper()

	return New(WithClock(func() time.Time { return at }))
}

// TestHandleKeyQuit pins that every quit key stops the UI and consumes the
// event.
func TestHandleKeyQuit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ev   *tcell.EventKey
	}{
		{"q", tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone)},
		{"Q", tcell.NewEventKey(tcell.KeyRune, 'Q', tcell.ModNone)},
		{"Esc", tcell.NewEventKey(tcell.KeyEsc, 0, tcell.ModNone)},
		{"Ctrl-C", tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := newKeyUI(t, baseTime)
			out := u.handleKey(tc.ev)

			assert.Nil(t, out)
			assert.True(t, u.stopped)
		})
	}
}

// TestHandleKeyHelpOverlay pins that any key closes the help overlay while
// it is open.
func TestHandleKeyHelpOverlay(t *testing.T) {
	t.Parallel()

	u := newKeyUI(t, baseTime)
	u.m.toggleHelp()
	require.True(t, u.m.helpOpen())

	out := u.handleKey(tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone))

	assert.Nil(t, out)
	assert.False(t, u.m.helpOpen())
}

// TestHandleKeyRunes pins pause, clear, help and focus selection.
func TestHandleKeyRunes(t *testing.T) {
	t.Parallel()

	t.Run("p toggles pause and freezes the traffic copy", func(t *testing.T) {
		t.Parallel()

		u := newKeyUI(t, baseTime)
		u.Request(events.Request{Family: events.FamilyV4, Type: "DISCOVER", Time: baseTime})

		out := u.handleKey(tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone))
		assert.Nil(t, out)
		assert.True(t, u.m.paused)
		assert.Len(t, u.m.frozen, 1)

		u.handleKey(tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone))
		assert.False(t, u.m.paused)
		assert.Nil(t, u.m.frozen)
	})

	t.Run("c clears traffic counters and rate history", func(t *testing.T) {
		t.Parallel()

		u := newKeyUI(t, baseTime)
		u.Request(events.Request{Family: events.FamilyV4, Type: "DISCOVER", Time: baseTime, Outcome: events.OutcomeDropped})

		out := u.handleKey(tcell.NewEventKey(tcell.KeyRune, 'c', tcell.ModNone))
		assert.Nil(t, out)
		assert.Empty(t, u.m.traffic.items())
		assert.Empty(t, u.m.counts)
		assert.Zero(t, u.m.tot.requests)
	})

	t.Run("question mark toggles help", func(t *testing.T) {
		t.Parallel()

		u := newKeyUI(t, baseTime)
		out := u.handleKey(tcell.NewEventKey(tcell.KeyRune, '?', tcell.ModNone))

		assert.Nil(t, out)
		assert.True(t, u.m.helpOpen())
	})

	t.Run("digits one through four set focus", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			r    rune
			want paneID
		}{
			{'1', paneTraffic},
			{'2', paneLeases},
			{'3', panePlugins},
			{'4', paneLog},
		}

		for _, tc := range tests {
			u := newKeyUI(t, baseTime)
			u.handleKey(tcell.NewEventKey(tcell.KeyRune, tc.r, tcell.ModNone))
			assert.Equal(t, tc.want, u.m.focus)
		}
	})

	t.Run("an out-of-range focus is ignored", func(t *testing.T) {
		t.Parallel()

		u := newKeyUI(t, baseTime)
		u.m.setFocus(paneLeases)
		u.m.setFocus(paneID(99))

		assert.Equal(t, paneLeases, u.m.focus)
	})
}

// TestHandleKeyFocusCycle pins Tab and Backtab walking focus in both
// directions, including the wraparound.
func TestHandleKeyFocusCycle(t *testing.T) {
	t.Parallel()

	u := newKeyUI(t, baseTime)
	require.Equal(t, paneTraffic, u.m.focus)

	u.handleKey(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone))
	assert.Equal(t, paneLeases, u.m.focus)

	u.handleKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone))
	assert.Equal(t, paneTraffic, u.m.focus)

	u.handleKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone))
	assert.Equal(t, paneLog, u.m.focus, "backtab wraps from the first pane to the last")
}

// TestHandleKeyScroll pins the scroll keys against a model whose geometry
// was set explicitly, including the follow flag switching off when
// scrolling away from the bottom and back on when returning to it.
func TestHandleKeyScroll(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) *UI {
		t.Helper()

		u := newKeyUI(t, baseTime)
		u.m.setFocus(paneTraffic)
		u.m.setGeometry(paneTraffic, 40, 50, 10)

		return u
	}

	t.Run("up scrolls back and switches off follow", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone))

		assert.Equal(t, 39, u.m.panes[paneTraffic].offset)
		assert.False(t, u.m.panes[paneTraffic].follow)
	})

	t.Run("down scrolls forward", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))

		assert.Equal(t, 41, u.m.panes[paneTraffic].offset)
	})

	t.Run("page up moves by a screenful", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone))

		assert.Equal(t, 30, u.m.panes[paneTraffic].offset)
	})

	t.Run("page down moves by a screenful", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone))

		assert.Equal(t, 50, u.m.panes[paneTraffic].offset)
	})

	t.Run("home jumps to the oldest row and stops following", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyHome, 0, tcell.ModNone))

		assert.Equal(t, 0, u.m.panes[paneTraffic].offset)
		assert.False(t, u.m.panes[paneTraffic].follow)
	})

	t.Run("end jumps to the newest row and resumes following for panes that follow", func(t *testing.T) {
		t.Parallel()

		u := setup(t)
		u.handleKey(tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone))

		assert.Equal(t, 40, u.m.panes[paneTraffic].offset)
		assert.True(t, u.m.panes[paneTraffic].follow)
	})

	t.Run("end does not resume following for a pane that never follows", func(t *testing.T) {
		t.Parallel()

		u := newKeyUI(t, baseTime)
		u.m.setFocus(paneLeases)
		u.m.setGeometry(paneLeases, 40, 50, 10)

		u.handleKey(tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone))

		assert.False(t, u.m.panes[paneLeases].follow)
	})
}

// TestHandleKeyUnhandled pins that a key nothing recognises is handed back
// unchanged.
func TestHandleKeyUnhandled(t *testing.T) {
	t.Parallel()

	u := newKeyUI(t, baseTime)
	ev := tcell.NewEventKey(tcell.KeyRune, 'z', tcell.ModNone)

	out := u.handleKey(ev)
	assert.Same(t, ev, out)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// listClients walks an intrusive lease-entry list from head to tail and
// collects the client identifiers, for asserting list order after unlink
// and pushFront.
func listClients(head *leaseEntry) []string {
	var out []string
	for e := head; e != nil; e = e.next {
		out = append(out, e.key.client)
	}

	return out
}
