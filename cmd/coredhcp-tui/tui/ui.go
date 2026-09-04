// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/coredhcp/coredhcp/events"
)

// Defaults for the options. The ring sizes are what one screen can show many
// times over, which is enough to scroll back through a burst without letting
// the process grow with uptime.
const (
	defaultVersion   = "(devel)"
	defaultRefresh   = 200 * time.Millisecond
	defaultHistory   = 500
	defaultMaxLeases = 10000
	defaultLogLines  = 500
)

// periodicRedraw is how often a frame is drawn even though nothing changed.
// The header counts up and half the columns are relative times, so the screen
// has to move once a second whether or not the server is busy.
const periodicRedraw = time.Second

// Row weights of the three bands below the header. The traffic and lease
// panes get the most room because they are what an operator watches; the
// counters and the log are reference.
const (
	topBandRatio = 3
	midBandRatio = 2
	logBandRatio = 1

	trafficRatio = 3
	leasesRatio  = 2
)

// Size of the help overlay, in cells.
const (
	helpWidth  = 66
	helpBorder = 2
)

// UI is the terminal interface. It implements events.Observer, so the server
// can report to it directly, and it is safe for concurrent use: the observer
// methods are called from the server's packet goroutines while the draw loop
// reads the same model.
//
// A UI runs once. Events and log lines are accepted before Run and after
// Stop; they simply have nowhere to be drawn.
type UI struct {
	version   string
	screen    tcell.Screen
	now       func() time.Time
	refresh   time.Duration
	history   int
	maxLeases int
	logLines  int

	m   *model
	log *logWriter

	mu      sync.Mutex
	started bool
	stopped bool
	done    chan struct{}
}

// Option configures a UI. Options are plain setters; New applies the defaults
// and rejects values that make no sense.
type Option func(*UI)

// WithVersion sets the version shown in the header.
func WithVersion(v string) Option {
	return func(u *UI) { u.version = v }
}

// WithScreen makes the UI draw on a screen the caller owns, which is how the
// tests drive it with tcell's simulation screen. Production leaves it unset
// and tview opens the terminal itself.
//
// The screen must already be initialised: Run does not call Init on it, and
// tcell's simulation screen resets its size and its event channel when it is
// initialised a second time.
func WithScreen(s tcell.Screen) Option {
	return func(u *UI) { u.screen = s }
}

// WithClock replaces time.Now, for tests that need a clock that does not move
// on its own.
func WithClock(now func() time.Time) Option {
	return func(u *UI) { u.now = now }
}

// WithRefresh sets how often the screen is redrawn. A frame is only drawn
// when something changed, so this is an upper bound on how stale the screen
// can be, not a frame rate.
func WithRefresh(d time.Duration) Option {
	return func(u *UI) { u.refresh = d }
}

// WithHistory sets how many requests the traffic pane keeps.
func WithHistory(n int) Option {
	return func(u *UI) { u.history = n }
}

// WithMaxLeases bounds the lease table. Past this many clients the least
// recently seen entry is dropped.
func WithMaxLeases(n int) Option {
	return func(u *UI) { u.maxLeases = n }
}

// WithLogLines sets how many log lines the log pane keeps.
func WithLogLines(n int) Option {
	return func(u *UI) { u.logLines = n }
}

// New builds a UI. It does not touch the terminal; nothing is drawn until Run.
func New(opts ...Option) *UI {
	u := &UI{
		version:   defaultVersion,
		now:       time.Now,
		refresh:   defaultRefresh,
		history:   defaultHistory,
		maxLeases: defaultMaxLeases,
		logLines:  defaultLogLines,
		done:      make(chan struct{}),
	}

	for _, opt := range opts {
		opt(u)
	}

	u.applyDefaults()

	u.m = newModel(u.now(), u.version, u.history, u.maxLeases, u.logLines)
	u.log = &logWriter{m: u.m, now: u.now}

	return u
}

// applyDefaults puts back any option that was given a value the UI cannot
// work with. An operator typo in a flag should cost them the setting, not the
// interface.
func (u *UI) applyDefaults() {
	if u.now == nil {
		u.now = time.Now
	}

	if u.refresh <= 0 {
		u.refresh = defaultRefresh
	}

	u.history = positive(u.history, defaultHistory)
	u.maxLeases = positive(u.maxLeases, defaultMaxLeases)
	u.logLines = positive(u.logLines, defaultLogLines)
}

// positive returns n, or fallback when n is not a usable size.
func positive(n, fallback int) int {
	if n <= 0 {
		return fallback
	}

	return n
}

// Listener records a socket the server bound.
func (u *UI) Listener(l events.Listener) { u.m.addListener(l) }

// Plugin records a plugin in a family's chain. The server calls this in chain
// order, which is what gives each plugin its position.
func (u *UI) Plugin(p events.Plugin) { u.m.addPlugin(p) }

// Request records one handled request. It is called from the goroutine that
// handled the packet, so it takes one lock, folds the event into the model
// and returns: no formatting, no allocation beyond the event's own strings,
// and nothing that could wait on the draw loop.
func (u *UI) Request(r events.Request) { u.m.addRequest(u.now(), r) }

// LogWriter returns the writer to point the server's log handler at. It is
// safe for concurrent use and holds a partial line until its newline arrives.
func (u *UI) LogWriter() io.Writer { return u.log }

// Run draws until the operator quits, ctx is done or Stop is called. It
// returns nil for all of those and an error only when the screen could not be
// opened. Calling it a second time, or after Stop, returns nil right away.
func (u *UI) Run(ctx context.Context) error {
	app, ok := u.begin()
	if !ok {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := u.build(app)

	// entered closes on tview's first draw, which is the point from which
	// app.Stop is guaranteed to reach a running event loop. Run closes it as
	// well once app.Run has returned, so a run that ended without ever
	// drawing does not leave the watcher waiting for a frame that is not
	// coming.
	entered := make(chan struct{})

	var once sync.Once

	drawn := func() { once.Do(func() { close(entered) }) }

	app.SetBeforeDrawFunc(func(tcell.Screen) bool {
		drawn()

		return false
	})

	var draws sync.WaitGroup

	draws.Add(1)

	go func() {
		defer draws.Done()

		u.redraw(ctx, app, p)
	}()

	runDone := make(chan struct{})
	watcher := u.watch(ctx, app, cancel, &draws, entered, runDone)

	err := app.Run()

	close(runDone)
	drawn()
	cancel()
	<-watcher
	draws.Wait()

	return err
}

// watch runs the shutdown in one place and in one order: wait for the first
// frame, so that stopping tview reaches a running event loop, then stop the
// draw loop, wait for it, and only then stop tview. The draw loop hands
// finished frames to tview through a queue that blocks until the event loop
// picks them up, so stopping the event loop first could strand it.
func (u *UI) watch(
	ctx context.Context,
	app *tview.Application,
	cancel context.CancelFunc,
	draws *sync.WaitGroup,
	entered, runDone <-chan struct{},
) <-chan struct{} {
	done := make(chan struct{})

	go func() {
		defer close(done)

		if !waitStop(ctx, u.done, runDone) {
			return
		}

		<-entered

		cancel()
		draws.Wait()
		app.Stop()
	}()

	return done
}

// waitStop blocks until something asks the run to stop: the caller's context,
// Stop, or the run ending on its own. It reports whether there is still a run
// left to stop.
func waitStop(ctx context.Context, stop, runDone <-chan struct{}) bool {
	select {
	case <-ctx.Done():
	case <-stop:
	case <-runDone:
		return false
	}

	return true
}

// begin claims the single run. It reports false when the UI was already run
// or already stopped, which is the caller asking for a screen that is never
// going to appear.
func (u *UI) begin() (*tview.Application, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.started || u.stopped {
		return nil, false
	}

	u.started = true

	return tview.NewApplication(), true
}

// Stop ends a running UI. It is safe to call before, during or after Run,
// from any goroutine, more than once, and it never blocks: it closes the
// channel the run watches and returns.
func (u *UI) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.stopped {
		return
	}

	u.stopped = true

	close(u.done)
}

// panes are the tview primitives one frame writes to.
type panes struct {
	pages    *tview.Pages
	header   *tview.TextView
	status   *tview.TextView
	footer   *tview.TextView
	counters *tview.TextView
	rate     *tview.TextView
	scroll   [paneCount]*tview.TextView
}

// build lays the screen out and hands the application its root primitive.
func (u *UI) build(app *tview.Application) *panes {
	p := &panes{
		pages:    newPages(),
		header:   newBar(),
		status:   newBar(),
		footer:   newBar(),
		counters: newPane(" counters "),
		rate:     newPane(" rate (last 60 s) "),
	}

	for id := paneTraffic; id < paneCount; id++ {
		p.scroll[id] = newPane(" " + id.title() + " ")
	}

	top := tview.NewFlex().
		AddItem(p.scroll[paneTraffic], 0, trafficRatio, false).
		AddItem(p.scroll[paneLeases], 0, leasesRatio, false)

	mid := tview.NewFlex().
		AddItem(p.scroll[panePlugins], 0, 1, false).
		AddItem(p.counters, 0, 1, false).
		AddItem(p.rate, 0, 1, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(p.header, 1, 0, false).
		AddItem(p.status, 1, 0, false).
		AddItem(top, 0, topBandRatio, false).
		AddItem(mid, 0, midBandRatio, false).
		AddItem(p.scroll[paneLog], 0, logBandRatio, false).
		AddItem(p.footer, 1, 0, false)

	p.pages.AddPage("main", root, true, true)
	p.pages.AddPage("help", helpOverlay(), true, false)

	if u.screen != nil {
		app.SetScreen(readyScreen{u.screen})
	}

	app.SetRoot(p.pages, true).SetInputCapture(u.handleKey)

	return p
}

// readyScreen hands tview a screen without letting it initialise the screen
// again. tview initialises whatever it is given, and tcell's simulation screen
// answers that by resetting its size and its event channel, which throws away
// the caller's setup and races anything already reading the screen.
type readyScreen struct {
	tcell.Screen
}

// Init reports success without touching the screen, because the caller
// initialised it before handing it over.
func (readyScreen) Init() error { return nil }

// newPages is the root primitive. It is the one container that clears the
// screen, so it is also the one that has to be told not to paint a background
// over the terminal's own.
func newPages() *tview.Pages {
	pages := tview.NewPages()
	pages.SetBackgroundColor(tcell.ColorDefault)

	return pages
}

// newBar is a one-line text view with no border, for the header, the status
// line and the footer.
func newBar() *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	useTerminalColours(tv)

	return tv
}

// useTerminalColours takes tview's black on white default off a text view so
// the screen inherits whatever the operator's terminal is set to, including
// its background. It is also what makes the colour reset in a tag go back to
// the terminal's own foreground instead of white.
func useTerminalColours(tv *tview.TextView) {
	tv.SetTextColor(tcell.ColorDefault)
	tv.SetBackgroundColor(tcell.ColorDefault)
}

// newPane is a bordered pane. Titles are plain ASCII on purpose: tview
// measures a title in bytes and prints it in cells, so markup or a multi-byte
// character in there costs the pane a stray ellipsis on its border.
func newPane(title string) *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetScrollable(false)
	useTerminalColours(tv)

	tv.SetBorder(true).
		SetBorderColor(tcell.ColorGray).
		SetTitle(title).
		SetTitleAlign(tview.AlignLeft).
		SetTitleColor(tcell.ColorGray)

	return tv
}

// helpOverlay is the key list, centred over the rest of the screen.
func helpOverlay() tview.Primitive {
	view := tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetText(helpText())
	useTerminalColours(view)

	view.SetBorder(true).
		SetTitle(" help ").
		SetTitleAlign(tview.AlignLeft)

	rows := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(view, len(helpLines())+helpBorder, 0, false).
		AddItem(nil, 0, 1, false)

	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(rows, helpWidth, 0, false).
		AddItem(nil, 0, 1, false)
}

// redraw is the frame loop. It takes a snapshot, renders every pane from it
// and hands the finished text to tview. Rendering happens here rather than
// inside the queued update so the event goroutine only does the parts that
// have to happen on it.
func (u *UI) redraw(ctx context.Context, app *tview.Application, p *panes) {
	ticker := time.NewTicker(u.refresh)
	defer ticker.Stop()

	var last time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		now := u.now()

		snap, ok := u.m.snapshot(now, now.Sub(last) >= periodicRedraw)
		if !ok {
			continue
		}

		last = now

		app.QueueUpdateDraw(func() { u.paint(snap, p) })
	}
}

// paint writes one frame into the primitives. It runs on tview's goroutine,
// which is the only place a pane's size can be read.
func (u *UI) paint(s snapshot, p *panes) {
	p.header.SetText(headerLine(s, barWidth(p.header)))
	p.status.SetText(statusLine(s, barWidth(p.status)))
	p.footer.SetText(footerLine(s, barWidth(p.footer)))

	u.paintScroll(paneTraffic, p.scroll[paneTraffic], s, trafficTitle(s), trafficLines, 0)
	u.paintScroll(paneLeases, p.scroll[paneLeases], s, leaseTitle(s), leaseLines, 1)
	u.paintScroll(panePlugins, p.scroll[panePlugins], s, " plugins ", pluginLines, 0)
	u.paintScroll(paneLog, p.scroll[paneLog], s, " log ", logLines, 0)

	paintFixed(p.counters, s, counterLines)
	paintFixed(p.rate, s, rateLines)

	if s.help {
		p.pages.ShowPage("help")
	} else {
		p.pages.HidePage("help")
	}
}

// paintScroll renders a scrollable pane and writes its geometry back to the
// model, which is what lets the scroll keys move by rows that are actually on
// screen. sticky is the number of leading lines, such as a column header,
// that stay put while the rest scrolls.
func (u *UI) paintScroll(
	id paneID,
	tv *tview.TextView,
	s snapshot,
	title string,
	render func(snapshot, int) []string,
	sticky int,
) {
	width, height := paneSize(tv)
	lines := render(s, width)

	head := lines[:min(sticky, len(lines))]
	body, start := visible(lines[len(head):], height-len(head), s.panes[id].offset, s.panes[id].follow)

	out := make([]string, 0, len(head)+len(body))
	out = append(out, head...)
	out = append(out, body...)

	tv.SetText(strings.Join(out, "\n"))
	tv.SetTitle(title)
	tv.SetTitleColor(titleColour(id == s.focus))

	u.m.setGeometry(id, start, len(lines)-len(head), max(height-len(head), 0))
}

// paintFixed renders a pane that does not scroll, cutting it to the rows that
// fit.
func paintFixed(tv *tview.TextView, s snapshot, render func(snapshot, int) []string) {
	width, height := paneSize(tv)

	lines := render(s, width)
	if len(lines) > height {
		lines = lines[:max(height, 0)]
	}

	tv.SetText(strings.Join(lines, "\n"))
}

// titleColour marks the pane the scroll keys are pointed at.
func titleColour(focused bool) tcell.Color {
	if focused {
		return tcell.ColorYellow
	}

	return tcell.ColorGray
}

// paneSize is a bordered pane's usable width and height.
func paneSize(tv *tview.TextView) (int, int) {
	_, _, width, height := tv.GetInnerRect()

	return max(width, 0), max(height, 0)
}

// barWidth is the width of a borderless row.
func barWidth(tv *tview.TextView) int {
	_, _, width, _ := tv.GetInnerRect()

	return max(width, 0)
}
