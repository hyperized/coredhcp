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

// The ring sizes are a screenful many times over: enough to scroll back through
// a burst without letting the process grow with uptime.
const (
	defaultVersion   = "(devel)"
	defaultRefresh   = 200 * time.Millisecond
	defaultHistory   = 500
	defaultMaxLeases = 10000
	defaultLogLines  = 500
)

// The header counts up and half the columns are relative times, so the screen
// has to move once a second whether or not the server is busy.
const periodicRedraw = time.Second

// Traffic and leases get the most room; the counters and the log are reference.
const (
	topBandRatio = 3
	midBandRatio = 2
	logBandRatio = 1

	trafficRatio = 3
	leasesRatio  = 2
)

const (
	helpWidth  = 66
	helpBorder = 2
)

// UI is the terminal interface: an events.Observer safe for concurrent use, since
// its observer methods run on the packet goroutines while the draw loop reads.
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

// Option configures a UI. Options are plain setters; New applies the defaults.
type Option func(*UI)

// WithVersion sets the version shown in the header.
func WithVersion(v string) Option {
	return func(u *UI) { u.version = v }
}

// WithScreen draws on a caller-owned screen, which must already be initialised:
// tview would otherwise reset a simulation screen's size and event channel.
func WithScreen(s tcell.Screen) Option {
	return func(u *UI) { u.screen = s }
}

// WithClock replaces time.Now, for tests that need a clock that does not move.
func WithClock(now func() time.Time) Option {
	return func(u *UI) { u.now = now }
}

// WithRefresh sets the redraw interval. A frame is only drawn when something
// changed, so this bounds staleness rather than setting a frame rate.
func WithRefresh(d time.Duration) Option {
	return func(u *UI) { u.refresh = d }
}

// WithHistory sets how many requests the traffic pane keeps.
func WithHistory(n int) Option {
	return func(u *UI) { u.history = n }
}

// WithMaxLeases bounds the lease table, dropping the least recently seen entry.
func WithMaxLeases(n int) Option {
	return func(u *UI) { u.maxLeases = n }
}

// WithLogLines sets how many log lines the log pane keeps.
func WithLogLines(n int) Option {
	return func(u *UI) { u.logLines = n }
}

// New builds a UI. It does not touch the terminal: nothing is drawn until Run.
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

// An operator's typo in a flag should cost them the setting, not the interface.
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

func positive(n, fallback int) int {
	if n <= 0 {
		return fallback
	}

	return n
}

// Listener records a socket the server bound.
func (u *UI) Listener(l events.Listener) { u.m.addListener(l) }

// Plugin records a plugin in a family's chain, in the order the server calls it.
func (u *UI) Plugin(p events.Plugin) { u.m.addPlugin(p) }

// Request records one handled request. It runs on the goroutine that handled the
// packet, so it folds the event in and returns without formatting anything.
func (u *UI) Request(r events.Request) { u.m.addRequest(u.now(), r) }

// LogWriter returns the writer for the server's log handler, safe for concurrent use.
func (u *UI) LogWriter() io.Writer { return u.log }

// Run draws until the operator quits, ctx is done or Stop is called, reporting an
// error only when the screen could not be opened. A second call returns nil.
func (u *UI) Run(ctx context.Context) error {
	app, ok := u.begin()
	if !ok {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := u.build(app)

	// entered closes on the first draw, from which app.Stop is sure to reach a
	// running event loop; Run closes it too, so a run that never drew is not stranded.
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

// Shutdown in one order: first frame, then the draw loop, then tview. The draw
// loop's queue blocks until the event loop drains it, so tview cannot go first.
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

// Reports whether there is still a run left to stop.
func waitStop(ctx context.Context, stop, runDone <-chan struct{}) bool {
	select {
	case <-ctx.Done():
	case <-stop:
	case <-runDone:
		return false
	}

	return true
}

// Claims the single run, reporting false when the UI was already run or stopped.
func (u *UI) begin() (*tview.Application, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.started || u.stopped {
		return nil, false
	}

	u.started = true

	return tview.NewApplication(), true
}

// Stop ends a running UI. It is safe from any goroutine, before, during or after
// Run, more than once, and it never blocks.
func (u *UI) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.stopped {
		return
	}

	u.stopped = true

	close(u.done)
}

type panes struct {
	pages    *tview.Pages
	header   *tview.TextView
	status   *tview.TextView
	footer   *tview.TextView
	counters *tview.TextView
	rate     *tview.TextView
	scroll   [paneCount]*tview.TextView
}

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

// tview initialises whatever screen it is given, and tcell's simulation screen
// answers that by resetting its size and event channel out from under the caller.
type readyScreen struct {
	tcell.Screen
}

// Init reports success without touching the screen: the caller initialised it.
func (readyScreen) Init() error { return nil }

// The one container that clears the screen, so also the one that has to be told
// not to paint over the terminal's own background.
func newPages() *tview.Pages {
	pages := tview.NewPages()
	pages.SetBackgroundColor(tcell.ColorDefault)

	return pages
}

func newBar() *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	useTerminalColours(tv)

	return tv
}

// Undoes tview's black-on-white default, which is also what makes a tag's reset
// return to the terminal's own foreground instead of to white.
func useTerminalColours(tv *tview.TextView) {
	tv.SetTextColor(tcell.ColorDefault)
	tv.SetBackgroundColor(tcell.ColorDefault)
}

// Titles are plain ASCII: tview measures a title in bytes and prints it in cells,
// so markup or a multi-byte rune there costs the border a stray ellipsis.
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

// Rendering happens here rather than inside the queued update, so the event
// goroutine only does the parts that have to happen on it.
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

// Runs on tview's goroutine, the only place a pane's size can be read.
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

// The geometry goes back to the model so the scroll keys move by rows actually on
// screen. sticky is the leading lines, such as a header, that stay put.
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

func paintFixed(tv *tview.TextView, s snapshot, render func(snapshot, int) []string) {
	width, height := paneSize(tv)

	lines := render(s, width)
	if len(lines) > height {
		lines = lines[:max(height, 0)]
	}

	tv.SetText(strings.Join(lines, "\n"))
}

func titleColour(focused bool) tcell.Color {
	if focused {
		return tcell.ColorYellow
	}

	return tcell.ColorGray
}

func paneSize(tv *tview.TextView) (int, int) {
	_, _, width, height := tv.GetInnerRect()

	return max(width, 0), max(height, 0)
}

func barWidth(tv *tview.TextView) int {
	_, _, width, _ := tv.GetInnerRect()

	return max(width, 0)
}
