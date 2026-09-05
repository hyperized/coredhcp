// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/cmd/coredhcp-tui/tui"
	"github.com/coredhcp/coredhcp/events"
)

// waitFor is deliberately generous: the draw loop ticks every few milliseconds
// here, so reaching it means something is wrong rather than slow.
const waitFor = 5 * time.Second

type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock(at time.Time) *clock { return &clock{at: at} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.at = c.at.Add(d)
}

// syncScreen serialises reads of the simulation screen against tview's writes:
// GetContents hands back the live buffer that Show and Sync overwrite in place.
type syncScreen struct {
	tcell.SimulationScreen

	mu sync.Mutex
}

func (s *syncScreen) Show() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.SimulationScreen.Show()
}

func (s *syncScreen) Sync() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.SimulationScreen.Sync()
}

func (s *syncScreen) Fini() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.SimulationScreen.Fini()
}

func (s *syncScreen) rows() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	cells, w, h := s.GetContents()

	out := make([]string, h)

	for y := range h {
		var b strings.Builder

		for x := range w {
			runes := cells[y*w+x].Runes
			if len(runes) == 0 {
				b.WriteRune(' ')

				continue
			}

			b.WriteRune(runes[0])
		}

		out[y] = strings.TrimRight(b.String(), " ")
	}

	return out
}

func newSyncScreen(t *testing.T) *syncScreen {
	t.Helper()

	sim := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, sim.Init())

	return &syncScreen{SimulationScreen: sim}
}

type harness struct {
	t      *testing.T
	ui     *tui.UI
	screen *syncScreen
	done   chan error
}

func newHarness(t *testing.T, width, height int, opts ...tui.Option) *harness {
	t.Helper()

	h := newPendingHarness(t, width, height, opts...)
	h.start()

	return h
}

// Separate from newHarness so a caller can feed events or log lines before Run.
func newPendingHarness(t *testing.T, width, height int, opts ...tui.Option) *harness {
	t.Helper()

	screen := newSyncScreen(t)
	screen.SetSize(width, height)

	ui := tui.New(append([]tui.Option{
		tui.WithScreen(screen),
		tui.WithRefresh(2 * time.Millisecond),
	}, opts...)...)

	return &harness{t: t, ui: ui, screen: screen, done: make(chan error, 1)}
}

func (h *harness) start() {
	h.t.Helper()

	go func() { h.done <- h.ui.Run(context.Background()) }()

	h.t.Cleanup(h.stop)

	h.waitText("coredhcp")
}

func (h *harness) stop() {
	h.t.Helper()

	h.ui.Stop()

	select {
	case err := <-h.done:
		require.NoError(h.t, err)
	case <-time.After(waitFor):
		h.t.Fatal("Run did not return after Stop")
	}
}

func (h *harness) key(key tcell.Key, r rune) {
	h.screen.InjectKey(key, r, tcell.ModNone)
}

func (h *harness) width() int {
	_, w, _ := h.screen.GetContents()

	return w
}

func (h *harness) row(y int) string {
	rows := h.screen.rows()
	if y < 0 || y >= len(rows) {
		return ""
	}

	return rows[y]
}

func (h *harness) text() string {
	return strings.Join(h.screen.rows(), "\n")
}

func (h *harness) waitFor(what string, want func(string) bool) {
	h.t.Helper()

	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if want(h.text()) {
			return
		}

		time.Sleep(time.Millisecond)
	}

	h.t.Fatalf("timed out waiting for %s, screen was:\n%s", what, h.text())
}

func (h *harness) waitText(want string) {
	h.t.Helper()

	h.waitFor(want, func(screen string) bool { return strings.Contains(screen, want) })
}

// Polls for the whole window: a single check can pass just by running too early.
func (h *harness) settles(unwanted string, d time.Duration) {
	h.t.Helper()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		require.NotContains(h.t, h.text(), unwanted)
		time.Sleep(time.Millisecond)
	}
}

// Polls for the whole window: a single check can pass just by running too early.
func (h *harness) staysText(want string, d time.Duration) {
	h.t.Helper()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		require.Contains(h.t, h.text(), want)
		time.Sleep(time.Millisecond)
	}
}

func runAsync(ctx context.Context, ui *tui.UI) <-chan error {
	done := make(chan error, 1)
	go func() { done <- ui.Run(ctx) }()

	return done
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(waitFor):
		t.Fatal("Run did not return in time")

		return nil
	}
}

func hammerStop(ui *tui.UI, n int) <-chan struct{} {
	done := make(chan struct{})

	var wg sync.WaitGroup

	wg.Add(n)

	for range n {
		go func() {
			defer wg.Done()

			ui.Stop()
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	return done
}

func prefix(t *testing.T, s string) netip.Prefix {
	t.Helper()

	addr, err := netip.ParseAddr(s)
	require.NoError(t, err)

	return netip.PrefixFrom(addr, addr.BitLen())
}

// The burst covers every outcome the panes grade differently.
func seed(t *testing.T, ui *tui.UI, at time.Time) {
	t.Helper()

	for _, l := range []events.Listener{
		{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"},
		{Family: events.FamilyV6, Address: "[::]:547"},
	} {
		ui.Listener(l)
	}

	for _, p := range []events.Plugin{
		{Family: events.FamilyV4, Name: "macfilter", Args: []string{"deny", "/etc/coredhcp/deny.txt"}},
		{Family: events.FamilyV4, Name: "file", Args: []string{"leases.txt", "autorefresh"}},
		{Family: events.FamilyV4, Name: "range", Args: []string{"10.0.0.5", "10.0.0.50"}},
		{Family: events.FamilyV6, Name: "redis", Args: []string{"redis://coredhcp:hunter2@10.0.0.9:6379"}},
	} {
		ui.Plugin(p)
	}

	for _, r := range []events.Request{
		{
			Time: at, Family: events.FamilyV4, Interface: "eth0", Type: "DISCOVER",
			ReplyType: "OFFER", ClientID: "aa:bb:cc:dd:ee:ff", Hostname: "laptop",
			Addresses: []netip.Prefix{prefix(t, "10.0.0.5")}, LeaseTime: time.Hour,
			Outcome: events.OutcomeReplied, Plugin: "range", Position: 3,
			Path: events.PathLayer2, Duration: 400 * time.Microsecond,
		},
		{
			Time: at.Add(2 * time.Millisecond), Family: events.FamilyV4, Interface: "eth0",
			Type: "REQUEST", ReplyType: "ACK", ClientID: "aa:bb:cc:dd:ee:ff", Hostname: "laptop",
			Addresses: []netip.Prefix{prefix(t, "10.0.0.5")}, LeaseTime: time.Hour,
			Outcome: events.OutcomeReplied, Plugin: "range", Position: 3,
			Path: events.PathBroadcast, Duration: 300 * time.Microsecond,
		},
		{
			Time: at.Add(time.Second), Family: events.FamilyV4, Interface: "eth0",
			Type: "DISCOVER", ClientID: "cc:dd:ee:ff:00:11",
			Outcome: events.OutcomeDropped, Plugin: "macfilter", Position: 1,
			Duration: 90 * time.Microsecond,
		},
		{
			Time: at.Add(2 * time.Second), Family: events.FamilyV6, Type: "SOLICIT",
			ReplyType: "ADVERTISE", ClientID: "00:01:00:01:2f:3a", Hostname: "printer",
			Addresses: []netip.Prefix{prefix(t, "2001:db8::5")}, LeaseTime: 2 * time.Hour,
			Outcome: events.OutcomeReplied, Path: events.PathUnicast,
			Duration: 2100 * time.Microsecond,
		},
		{
			Time: at.Add(3 * time.Second), Family: events.FamilyV6, Type: "REQUEST",
			ReplyType: "REPLY", ClientID: "00:01:00:01:2f:3a", Hostname: "printer",
			Addresses: []netip.Prefix{prefix(t, "2001:db8::5")}, LeaseTime: 2 * time.Hour,
			Outcome: events.OutcomeReplied, Path: events.PathUnicast,
			Duration: 700 * time.Microsecond,
		},
		{
			Time: at.Add(4 * time.Second), Family: events.FamilyV4, Interface: "eth0",
			Type: "REQUEST", ReplyType: "NAK", ClientID: "11:22:33:44:55:66",
			Outcome: events.OutcomeReplied, Plugin: "file", Position: 2,
			Path: events.PathBroadcast, Duration: 250 * time.Microsecond,
		},
		{
			Time: at.Add(5 * time.Second), Family: events.FamilyV4, Interface: "eth0",
			Outcome: events.OutcomeParseError, Error: "short packet: 12 bytes",
		},
	} {
		ui.Request(r)
	}

	for _, line := range []string{
		`time=2026-09-04T21:04:10.001+02:00 level=INFO msg="Listen 0.0.0.0:67" prefix=server4`,
		`time=2026-09-04T21:04:10.002+02:00 level=INFO msg="Listen [::]:547" prefix=server6`,
		`time=2026-09-04T21:04:15.100+02:00 level=WARN msg="lease file reloaded" prefix=plugins/file leases=42`,
	} {
		_, err := ui.LogWriter().Write([]byte(line + "\n"))
		require.NoError(t, err)
	}
}

func TestScreenDump(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 4, 21, 4, 11, 123000000, time.UTC)
	c := newClock(at)

	h := newHarness(t, 100, 35, tui.WithClock(c.now), tui.WithVersion("v0.2.0"))

	seed(t, h.ui, at)
	c.advance(90 * time.Minute)
	h.waitText("HEALTHY")

	require.Equal(t, 100, h.width())
	require.Contains(t, h.row(0), "coredhcp")

	t.Logf("\n%s", h.text())
}

func TestStopBeforeRunReturnsNilImmediately(t *testing.T) {
	t.Parallel()

	ui := tui.New()
	ui.Stop()

	require.NoError(t, waitRun(t, runAsync(context.Background(), ui)))
}

func TestSecondRunReturnsNilAfterFirstReturns(t *testing.T) {
	t.Parallel()

	ui := tui.New(tui.WithScreen(newSyncScreen(t)), tui.WithRefresh(2*time.Millisecond))

	first := runAsync(context.Background(), ui)
	ui.Stop()
	require.NoError(t, waitRun(t, first))

	require.NoError(t, waitRun(t, runAsync(context.Background(), ui)))
}

func TestContextCancellationEndsRun(t *testing.T) {
	t.Parallel()

	ui := tui.New(tui.WithScreen(newSyncScreen(t)), tui.WithRefresh(2*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())

	done := runAsync(ctx, ui)
	cancel()

	require.NoError(t, waitRun(t, done))
}

func TestStopIdempotentBeforeRun(t *testing.T) {
	t.Parallel()

	ui := tui.New()

	select {
	case <-hammerStop(ui, 20):
	case <-time.After(waitFor):
		t.Fatal("Stop blocked before Run")
	}

	require.NoError(t, waitRun(t, runAsync(context.Background(), ui)))
}

func TestStopIdempotentDuringRun(t *testing.T) {
	t.Parallel()

	ui := tui.New(tui.WithScreen(newSyncScreen(t)), tui.WithRefresh(2*time.Millisecond))
	done := runAsync(context.Background(), ui)

	select {
	case <-hammerStop(ui, 20):
	case <-time.After(waitFor):
		t.Fatal("Stop blocked during Run")
	}

	require.NoError(t, waitRun(t, done))
}

func TestStopIdempotentAfterRun(t *testing.T) {
	t.Parallel()

	ui := tui.New(tui.WithScreen(newSyncScreen(t)), tui.WithRefresh(2*time.Millisecond))
	done := runAsync(context.Background(), ui)
	ui.Stop()
	require.NoError(t, waitRun(t, done))

	select {
	case <-hammerStop(ui, 20):
	case <-time.After(waitFor):
		t.Fatal("Stop blocked after Run")
	}
}

func TestEventsAcceptedBeforeRunShowOnScreen(t *testing.T) {
	t.Parallel()

	h := newPendingHarness(t, 200, 35)

	h.ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"})
	h.ui.Plugin(events.Plugin{Family: events.FamilyV4, Name: "range"})
	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", Outcome: events.OutcomeDropped, Plugin: "macfilter",
	})

	_, err := h.ui.LogWriter().Write([]byte("preboot line\n"))
	require.NoError(t, err)

	h.start()

	h.waitText("preboot line")
	require.Contains(t, h.text(), "0.0.0.0:67")
	require.Contains(t, h.text(), "macfilter")
}

func TestEventsAndLogAcceptedAfterStopDoNotPanic(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 80, 24)
	h.ui.Stop()

	require.NotPanics(t, func() {
		h.ui.Listener(events.Listener{Family: events.FamilyV6, Address: "[::]:547"})
		h.ui.Plugin(events.Plugin{Family: events.FamilyV6, Name: "range"})
		h.ui.Request(events.Request{Family: events.FamilyV6, Type: "SOLICIT", Outcome: events.OutcomeDropped})

		_, err := h.ui.LogWriter().Write([]byte("postmortem\n"))
		require.NoError(t, err)
	})
}

func TestQuitKeysEndRun(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  tcell.Key
		r    rune
	}{
		{name: "q", key: tcell.KeyRune, r: 'q'},
		{name: "esc", key: tcell.KeyEsc},
		{name: "ctrl-c", key: tcell.KeyCtrlC},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, 80, 24)
			h.key(tc.key, tc.r)
		})
	}
}

func TestDefaultVersionIsDevel(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 80, 24)

	h.waitText("(devel)")
}

func TestWithVersionShowsInHeader(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 80, 24, tui.WithVersion("v9.9.9"))

	h.waitText("v9.9.9")
}

func TestInvalidOptionsFallBackToDefaults(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opt  tui.Option
	}{
		{name: "zero refresh", opt: tui.WithRefresh(0)},
		{name: "negative refresh", opt: tui.WithRefresh(-time.Second)},
		{name: "zero history", opt: tui.WithHistory(0)},
		{name: "negative history", opt: tui.WithHistory(-5)},
		{name: "zero max leases", opt: tui.WithMaxLeases(0)},
		{name: "negative log lines", opt: tui.WithLogLines(-1)},
		{name: "nil clock", opt: tui.WithClock(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, 100, 30, tc.opt)

			h.ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67"})
			h.ui.Request(events.Request{
				Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
				ClientID: "aa:bb:cc:dd:ee:ff", Outcome: events.OutcomeReplied,
			})

			h.waitText("DISCOVER")
		})
	}
}

func TestWithHistoryBoundsTrafficPane(t *testing.T) {
	t.Parallel()

	const n = 5

	h := newHarness(t, 100, 30, tui.WithHistory(n))

	for i := range n + 3 {
		h.ui.Request(events.Request{
			Family: events.FamilyV4, Type: "DISCOVER", Outcome: events.OutcomeDropped,
			ClientID: fmt.Sprintf("client-%02d", i),
		})
	}

	h.waitText("client-07")
	require.NotContains(t, h.text(), "client-00")
}

func TestWithMaxLeasesBoundsLeaseTable(t *testing.T) {
	t.Parallel()

	const n = 3

	h := newHarness(t, 100, 30, tui.WithMaxLeases(n))

	for i := range n + 4 {
		h.ui.Request(events.Request{
			Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
			ClientID: fmt.Sprintf("client-%02d", i), Outcome: events.OutcomeReplied,
		})
	}

	h.waitText(fmt.Sprintf("client-%02d", n+3))
	h.waitText(fmt.Sprintf("%d offered, 0 confirmed", n))
}

func TestWithLogLinesBoundsLogPane(t *testing.T) {
	t.Parallel()

	const n = 3

	h := newHarness(t, 100, 30, tui.WithLogLines(n))

	for i := range n + 4 {
		_, err := fmt.Fprintf(h.ui.LogWriter(), "line-%02d\n", i)
		require.NoError(t, err)
	}

	h.waitText("line-06")
	require.NotContains(t, h.text(), "line-00")
}

func TestWithClockDrivesUptime(t *testing.T) {
	t.Parallel()

	c := newClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHarness(t, 100, 30, tui.WithClock(c.now))

	h.waitText("up 00:00:00")

	c.advance(time.Minute)
	h.waitText("up 00:01:00")
}

func TestListenerShowsInPluginsPaneAndHeaderCount(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 100, 30)

	h.waitText("listeners=0")

	h.ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67", Interface: "eth0"})

	h.waitText("listeners=1")
	h.waitText("0.0.0.0:67 (eth0)")
}

func TestPluginChainNumberedAndRedacted(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	h.ui.Plugin(events.Plugin{
		Family: events.FamilyV6, Name: "redis",
		Args: []string{"redis://coredhcp:hunter2@10.0.0.9:6379"},
	})
	h.ui.Plugin(events.Plugin{
		Family: events.FamilyV6, Name: "range",
		Args: []string{"2001:db8::1", "2001:db8::ff"},
	})

	h.waitText("range")
	require.Contains(t, h.text(), "1 redis")
	require.Contains(t, h.text(), "2 range")
	require.Contains(t, h.text(), "coredhcp:***@")
	require.NotContains(t, h.text(), "hunter2")
}

func TestConfirmedLeaseFromDiscoverOfferRequestAck(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
		ClientID: "aa:bb:cc:dd:ee:ff", Addresses: []netip.Prefix{prefix(t, "10.0.0.5")},
		LeaseTime: time.Hour, Outcome: events.OutcomeReplied,
	})
	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "REQUEST", ReplyType: "ACK",
		ClientID: "aa:bb:cc:dd:ee:ff", Addresses: []netip.Prefix{prefix(t, "10.0.0.5")},
		LeaseTime: time.Hour, Outcome: events.OutcomeReplied,
	})

	h.waitText("1 confirmed")
	require.Contains(t, h.text(), "ee:ff")
}

func TestStatusLineGrading(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		seed func(ui *tui.UI)
		want string
	}{
		{
			name: "no listeners",
			seed: func(*tui.UI) {},
			want: "FAILING",
		},
		{
			name: "send error in the last minute",
			seed: func(ui *tui.UI) {
				ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67"})
				ui.Request(events.Request{
					Family: events.FamilyV4, Type: "REQUEST", Outcome: events.OutcomeSendError,
					Error: "write: connection refused", Time: at,
				})
			},
			want: "FAILING",
		},
		{
			name: "parse error in the last minute",
			seed: func(ui *tui.UI) {
				ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67"})
				ui.Request(events.Request{
					Family: events.FamilyV4, Outcome: events.OutcomeParseError,
					Error: "short packet", Time: at,
				})
			},
			want: "DEGRADED",
		},
		{
			name: "no errors",
			seed: func(ui *tui.UI) {
				ui.Listener(events.Listener{Family: events.FamilyV4, Address: "0.0.0.0:67"})
				ui.Request(events.Request{
					Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
					ClientID: "aa:bb:cc:dd:ee:ff", Outcome: events.OutcomeReplied, Time: at,
				})
			},
			want: "HEALTHY",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newClock(at)
			h := newHarness(t, 100, 30, tui.WithClock(c.now))

			tc.seed(h.ui)

			h.waitText(tc.want)
		})
	}
}

func TestHostnameMarkupAndControlCharsSanitised(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", ReplyType: "OFFER",
		ClientID: "c1", Hostname: "[red]evil\x07host",
		Outcome: events.OutcomeReplied,
	})

	h.waitText("evil")
	require.Contains(t, h.text(), "[red]evil.host")
	require.NotContains(t, h.text(), "\x07")
}

func TestLogWriterRendersParsedFields(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	line := `time=2026-09-04T21:04:10.001+02:00 level=INFO msg="Listen [::]:547" prefix=server6`
	_, err := h.ui.LogWriter().Write([]byte(line + "\n"))
	require.NoError(t, err)

	h.waitText("Listen [::]:547")
	require.Contains(t, h.text(), "21:04:10")
	require.Contains(t, h.text(), "INFO")
	require.Contains(t, h.text(), "server6")
}

func TestLogWriterRendersUnparsedLineRaw(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	const raw = "plain log line without any key value pairs"

	_, err := h.ui.LogWriter().Write([]byte(raw + "\n"))
	require.NoError(t, err)

	h.waitText(raw)
}

func TestLogWriterHoldsPartialLineUntilNewline(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	_, err := h.ui.LogWriter().Write([]byte("half a line no newline yet"))
	require.NoError(t, err)

	h.settles("half a line", 20*time.Millisecond)

	_, err = h.ui.LogWriter().Write([]byte(" now complete\n"))
	require.NoError(t, err)

	h.waitText("half a line no newline yet now complete")
}

func TestPauseKeyFreezesTrafficPane(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 160, 30)

	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", ClientID: "before-pause", Outcome: events.OutcomeDropped,
	})
	h.waitText("before-pause")

	h.key(tcell.KeyRune, 'p')
	h.waitText("PAUSED")
	h.waitText("paused")

	h.ui.Request(events.Request{
		Family: events.FamilyV4, Type: "DISCOVER", ClientID: "after-pause", Outcome: events.OutcomeDropped,
	})
	h.settles("after-pause", 20*time.Millisecond)

	h.key(tcell.KeyRune, 'p')
	h.waitText("after-pause")
}

func TestHelpOverlayTogglesOnAnyKey(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 100, 30)

	h.key(tcell.KeyRune, '?')
	h.waitText("Home, End")

	h.key(tcell.KeyRune, 'x')
	h.waitFor("help overlay closed", func(s string) bool { return !strings.Contains(s, "Home, End") })
}

func TestFocusMovesWithTabAndDigitKeys(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 100, 16)

	for i := range 20 {
		h.ui.Request(events.Request{
			Family: events.FamilyV4, Type: "DISCOVER", Outcome: events.OutcomeDropped,
			ClientID: fmt.Sprintf("t%02d", i),
		})
	}

	h.waitText("t19")

	// Focus is observed indirectly: only the focused traffic pane stops following on Up.
	h.key(tcell.KeyUp, 0)
	h.waitFor("traffic pane to stop following", func(s string) bool { return !strings.Contains(s, "t19") })

	h.key(tcell.KeyEnd, 0)
	h.waitText("t19")

	h.key(tcell.KeyTab, 0)
	h.key(tcell.KeyUp, 0)
	h.staysText("t19", 20*time.Millisecond)

	h.key(tcell.KeyRune, '1')
	h.key(tcell.KeyUp, 0)
	h.waitFor("traffic pane to stop following again", func(s string) bool { return !strings.Contains(s, "t19") })

	for _, r := range []rune{'2', '3', '4'} {
		h.key(tcell.KeyRune, '1')
		h.key(tcell.KeyEnd, 0)
		h.waitText("t19")

		h.key(tcell.KeyRune, r)
		h.key(tcell.KeyUp, 0)
		h.staysText("t19", 20*time.Millisecond)
	}

	h.key(tcell.KeyRune, '1')
	h.key(tcell.KeyEnd, 0)
	h.waitText("t19")

	h.key(tcell.KeyBacktab, 0)
	h.key(tcell.KeyUp, 0)
	h.staysText("t19", 20*time.Millisecond)
}

func TestScrollingMovesByRowsHomeEndPgUpPgDn(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 100, 16)

	for i := range 40 {
		h.ui.Request(events.Request{
			Family: events.FamilyV4, Type: "DISCOVER", Outcome: events.OutcomeDropped,
			ClientID: fmt.Sprintf("r%02d", i),
		})
	}

	h.waitText("r39")
	require.NotContains(t, h.text(), "r00")

	h.key(tcell.KeyUp, 0)
	h.waitFor("stopped following the newest row", func(s string) bool { return !strings.Contains(s, "r39") })

	h.key(tcell.KeyEnd, 0)
	h.waitText("r39")

	h.key(tcell.KeyHome, 0)
	h.waitText("r00")

	h.key(tcell.KeyPgDn, 0)
	h.waitFor("paged down a screenful", func(s string) bool { return !strings.Contains(s, "r00") })

	h.key(tcell.KeyPgUp, 0)
	h.waitText("r00")
}

func TestClearKeyResetsTrafficAndCountersKeepsLeasesAndLog(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, 160, 35, tui.WithClock(newClock(at).now))

	seed(t, h.ui, at)
	h.waitText("2 confirmed")
	h.waitText("lease file reloaded")

	h.key(tcell.KeyRune, 'c')

	h.waitText("waiting for the first request")
	require.NotContains(t, h.text(), "DISCOVER")
	require.Contains(t, h.text(), "2 confirmed")
	require.Contains(t, h.text(), "lease file reloaded")
}
