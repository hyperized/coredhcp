// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/coredhcp/coredhcp/events"
)

// Bounds on what one event may contribute to the model. Hostnames, client
// identifiers and error texts come off the wire, so they are cut down before
// they are stored rather than only before they are drawn.
const (
	maxIDLen    = 64
	maxNameLen  = 48
	maxErrLen   = 160
	maxWordLen  = 24
	maxAddrs    = 4
	maxFamilies = 8
	maxTypeKeys = 16
)

// rateBuckets is the length of the per-second histories behind the rate pane:
// one minute, which is also the window the status line grades on.
const rateBuckets = 60

// pathCount is the number of events.ReplyPath values, used to size the path
// breakdown array.
const pathCount = 4

// renderFamilies is the order the per-family panes are drawn in. Events for
// any other family are still counted, they just have no section of their own.
var renderFamilies = []events.Family{events.FamilyV4, events.FamilyV6}

// paneID identifies a scrollable pane. The order is the order Tab walks.
type paneID int

// The scrollable panes.
const (
	paneTraffic paneID = iota
	paneLeases
	panePlugins
	paneLog
	paneCount
)

// follows reports whether a pane sticks to its newest row until the operator
// scrolls away from it.
func (p paneID) follows() bool { return p == paneTraffic || p == paneLog }

// title is the pane's name in its border.
func (p paneID) title() string {
	switch p {
	case paneTraffic:
		return "traffic"
	case paneLeases:
		return "leases"
	case panePlugins:
		return "plugins"
	case paneLog:
		return "log"
	case paneCount:
	}

	return ""
}

// paneView is a pane's scroll position. offset is where the operator put the
// window; start, total and height are written back by the draw loop so the
// scroll keys can move relative to what is actually on screen.
type paneView struct {
	offset int
	follow bool
	start  int
	total  int
	height int
}

// ring is a fixed size FIFO. The traffic and log panes both keep the newest N
// entries and nothing else, so memory does not grow with uptime.
type ring[T any] struct {
	buf   []T
	start int
	n     int
}

// newRing allocates a ring holding at most capacity entries.
func newRing[T any](capacity int) *ring[T] {
	return &ring[T]{buf: make([]T, max(capacity, 1))}
}

// push appends v, dropping the oldest entry once the ring is full.
func (r *ring[T]) push(v T) {
	if r.n < len(r.buf) {
		r.buf[(r.start+r.n)%len(r.buf)] = v
		r.n++

		return
	}

	r.buf[r.start] = v
	r.start = (r.start + 1) % len(r.buf)
}

// items copies the ring out, oldest first.
func (r *ring[T]) items() []T {
	out := make([]T, r.n)
	for i := range out {
		out[i] = r.buf[(r.start+i)%len(r.buf)]
	}

	return out
}

// reset empties the ring and lets the entries be collected.
func (r *ring[T]) reset() {
	clear(r.buf)
	r.start, r.n = 0, 0
}

// rateRing counts events per second over the last minute. It is a ring of
// one-second buckets with head being the second the newest bucket counts;
// advancing zeroes the buckets that were skipped so an idle minute reads as
// zeroes and not as stale peaks.
type rateRing struct {
	buckets [rateBuckets]uint32
	sec     int64
	head    int
	primed  bool
}

// advance moves the head to the second at, clearing what it passes over.
func (r *rateRing) advance(at time.Time) {
	sec := at.Unix()

	switch {
	case !r.primed:
		r.primed, r.sec = true, sec
	case sec <= r.sec:
	case sec-r.sec >= rateBuckets:
		r.buckets = [rateBuckets]uint32{}
		r.head, r.sec = 0, sec
	default:
		for range sec - r.sec {
			r.head = (r.head + 1) % rateBuckets
			r.buckets[r.head] = 0
		}

		r.sec = sec
	}
}

// add counts one event at time at. An event stamped before the head second
// lands in the head bucket: the server's clock is the same clock, so this only
// happens on a step backwards, and losing a second of resolution beats
// rewriting history.
func (r *rateRing) add(at time.Time) {
	r.advance(at)
	r.buckets[r.head]++
}

// series ages the ring to now and returns the buckets oldest first.
func (r *rateRing) series(now time.Time) []uint32 {
	r.advance(now)

	out := make([]uint32, rateBuckets)
	for i := range out {
		out[i] = r.buckets[(r.head+1+i)%rateBuckets]
	}

	return out
}

// reset drops the history without disturbing the head second.
func (r *rateRing) reset() {
	r.buckets = [rateBuckets]uint32{}
}

// sum adds up a series, for the "N in 60 s" labels.
func sum(values []uint32) uint64 {
	var total uint64
	for _, v := range values {
		total += uint64(v)
	}

	return total
}

// peak is the largest value in a series, which is what the sparklines scale
// against.
func peak(values []uint32) uint32 {
	var top uint32
	for _, v := range values {
		top = max(top, v)
	}

	return top
}

// familyCounters is everything the counters pane shows for one family.
type familyCounters struct {
	total       uint64
	in          map[string]uint64
	out         map[string]uint64
	dropped     uint64
	parseErrs   uint64
	unsupported uint64
	sendErrs    uint64
	paths       [pathCount]uint64
}

// newFamilyCounters returns zeroed counters with usable maps.
func newFamilyCounters() *familyCounters {
	return &familyCounters{in: map[string]uint64{}, out: map[string]uint64{}}
}

// clone copies the counters so the draw loop can read them outside the lock.
func (c *familyCounters) clone() familyCounters {
	out := *c
	out.in = maps.Clone(c.in)
	out.out = maps.Clone(c.out)

	return out
}

// add folds one request into the counters.
func (c *familyCounters) add(r events.Request) {
	c.total++
	bumpKey(c.in, r.Type)

	if r.ReplyType != "" {
		bumpKey(c.out, r.ReplyType)
	}

	if int(r.Path) < pathCount {
		c.paths[r.Path]++
	}

	switch r.Outcome {
	case events.OutcomeDropped:
		c.dropped++
	case events.OutcomeParseError:
		c.parseErrs++
	case events.OutcomeUnsupported:
		c.unsupported++
	case events.OutcomeSendError:
		c.sendErrs++
	case events.OutcomeReplied, events.OutcomeNoReply:
		// Neither is a problem: the message type is already visible in
		// the in map and total, and nothing went wrong.
	}
}

// bumpKey counts one message type. The key space is the DHCP message types,
// but the map is capped anyway: a packet the library could not name must not
// be able to grow the map without bound.
func bumpKey(m map[string]uint64, key string) {
	if key == "" {
		key = "?"
	}

	if _, known := m[key]; !known && len(m) >= maxTypeKeys {
		key = "other"
	}

	m[key]++
}

// chainLink is one plugin in a family's chain, with what the traffic did to
// it: how often it was reached, and how often it was the link that ended the
// chain with a reply or with a drop.
type chainLink struct {
	name    string
	args    []string
	reached uint64
	replied uint64
	dropped uint64
}

// totals are the server-wide counters in the header, plus the timestamps the
// status line grades on.
type totals struct {
	requests  uint64
	issued    uint64
	confirmed uint64
	dropped   uint64
	errors    uint64

	lastRequest time.Time
	lastSoftErr time.Time
	lastSendErr time.Time
}

// model is everything the UI knows, guarded by one mutex. The observer
// methods write it from the server's packet goroutines; the draw loop reads it
// once per frame through snapshot.
type model struct {
	mu sync.Mutex

	dirty   bool
	started time.Time
	version string

	listeners []events.Listener
	chains    map[events.Family][]*chainLink
	counts    map[events.Family]*familyCounters

	traffic *ring[events.Request]
	frozen  []events.Request
	logs    *ring[logEntry]
	leases  *leaseTable

	reqRate rateRing
	errRate rateRing
	tot     totals

	paused bool
	help   bool
	focus  paneID
	panes  [paneCount]paneView
}

// newModel builds the model with the ring sizes the options settled on.
func newModel(started time.Time, version string, history, leases, logLines int) *model {
	m := &model{
		started: started,
		version: version,
		chains:  map[events.Family][]*chainLink{},
		counts:  map[events.Family]*familyCounters{},
		traffic: newRing[events.Request](history),
		logs:    newRing[logEntry](logLines),
		leases:  newLeaseTable(leases),
	}

	for i := range m.panes {
		m.panes[i].follow = paneID(i).follows()
	}

	return m
}

// snapshot is the value copy the draw loop renders from. Taking it is the
// only place the model is read, and it happens under a single lock so a frame
// cannot show one pane's state next to another pane's.
type snapshot struct {
	now     time.Time
	uptime  time.Duration
	version string

	listeners []events.Listener
	chains    map[events.Family][]chainLink
	counts    map[events.Family]familyCounters

	traffic []events.Request
	leases  []leaseRow
	logs    []logEntry

	// leaseCounts is how many entries the whole table holds in each state,
	// which is more than the rows above when the table is larger than one
	// frame's worth. history is the traffic ring's size, for its title.
	leaseCounts [leaseStateCount]int
	history     int

	reqRate []uint32
	errRate []uint32
	tot     totals

	paused bool
	help   bool
	focus  paneID
	panes  [paneCount]paneView
}

// addListener records a socket the server bound.
func (m *model) addListener(l events.Listener) {
	l.Address, _ = clip(l.Address, maxNameLen)
	l.Interface, _ = clip(l.Interface, maxWordLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.listeners = append(m.listeners, l)
	m.dirty = true
}

// addPlugin appends a plugin to its family's chain. The server calls this in
// chain order, which is what gives each link its position.
func (m *model) addPlugin(p events.Plugin) {
	link := &chainLink{name: p.Name, args: slices.Clone(p.Args)}
	link.name, _ = clip(link.name, maxWordLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.chains[p.Family] = append(m.chains[p.Family], link)
	m.dirty = true
}

// addRequest folds one handled request into every part of the model: the
// traffic ring, the counters, the rate histories, the lease table and the
// chain's per-link tallies. This runs on the server's packet path, so it
// allocates as little as it can and never formats anything.
func (m *model) addRequest(now time.Time, r events.Request) {
	r = boundRequest(r)
	if r.Time.IsZero() {
		r.Time = now
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.dirty = true
	m.traffic.push(r)
	m.tot.requests++
	m.tot.lastRequest = r.Time
	m.reqRate.add(r.Time)

	m.family(r.Family).add(r)
	m.recordOutcome(r)
	m.recordChain(r)
	m.recordLease(r)
}

// boundRequest cuts the event's strings and address list down to what the
// panes can show, so the traffic ring's memory is bounded by its length and
// not by what a client put in a hostname option.
func boundRequest(r events.Request) events.Request {
	r.Interface, _ = clip(r.Interface, maxWordLen)
	r.Type, _ = clip(r.Type, maxWordLen)
	r.ReplyType, _ = clip(r.ReplyType, maxWordLen)
	r.Plugin, _ = clip(r.Plugin, maxWordLen)
	r.ClientID, _ = clip(r.ClientID, maxIDLen)
	r.Hostname, _ = clip(r.Hostname, maxNameLen)
	r.Error, _ = clip(r.Error, maxErrLen)

	if len(r.Addresses) > maxAddrs {
		r.Addresses = r.Addresses[:maxAddrs]
	}

	r.Addresses = slices.Clone(r.Addresses)

	return r
}

// family returns the counters for a family, creating them on first sight. The
// map is capped: Family is a byte and the events package does not promise it
// is one of two values.
func (m *model) family(f events.Family) *familyCounters {
	if c, ok := m.counts[f]; ok {
		return c
	}

	if len(m.counts) >= maxFamilies {
		return newFamilyCounters()
	}

	c := newFamilyCounters()
	m.counts[f] = c

	return c
}

// recordOutcome updates the server-wide tallies and the error history the
// status line grades on. Caller holds the lock.
func (m *model) recordOutcome(r events.Request) {
	switch r.Outcome {
	case events.OutcomeDropped:
		m.tot.dropped++
	case events.OutcomeParseError, events.OutcomeUnsupported:
		m.tot.errors++
		m.tot.lastSoftErr = r.Time
		m.errRate.add(r.Time)
	case events.OutcomeSendError:
		m.tot.errors++
		m.tot.lastSendErr = r.Time
		m.errRate.add(r.Time)
	case events.OutcomeReplied, events.OutcomeNoReply:
		// Neither dropped anything nor errored, so neither counter nor
		// error timestamp moves.
	}
}

// recordChain attributes the request to the plugins that saw it. The event
// only names the link that ended the chain, but chain order is enough to know
// the rest: with a stopping link at position p, links 1..p ran; with no
// stopping link every plugin ran. A packet that never reached the chain
// reaches nobody. Caller holds the lock.
func (m *model) recordChain(r events.Request) {
	links := m.chains[r.Family]
	if len(links) == 0 {
		return
	}

	if r.Outcome == events.OutcomeParseError || r.Outcome == events.OutcomeUnsupported {
		return
	}

	stop := r.Position
	if stop <= 0 || stop > len(links) {
		for _, l := range links {
			l.reached++
		}

		return
	}

	for _, l := range links[:stop] {
		l.reached++
	}

	switch r.Outcome {
	case events.OutcomeReplied, events.OutcomeSendError:
		links[stop-1].replied++
	case events.OutcomeDropped:
		links[stop-1].dropped++
	case events.OutcomeNoReply:
		// The chain ran and stopped here, but nothing was sent and
		// nothing was dropped, so the stopping link gets neither tally.
	case events.OutcomeParseError, events.OutcomeUnsupported:
	}
}

// addLog stores one log line as it arrived. Parsing happens at draw time: the
// writer is called from wherever the server logs, and the ring holds far more
// lines than the pane ever shows.
func (m *model) addLog(now time.Time, raw string) {
	raw, _ = clip(raw, maxLogLineLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logs.push(logEntry{at: now, raw: raw})
	m.dirty = true
}

// snapshot copies out what a frame needs. When force is false and nothing has
// changed since the last call it reports false and copies nothing.
func (m *model) snapshot(now time.Time, force bool) (snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.dirty && !force {
		return snapshot{}, false
	}

	m.dirty = false

	snap := snapshot{
		now:       now,
		uptime:    now.Sub(m.started),
		version:   m.version,
		listeners: slices.Clone(m.listeners),
		chains:    cloneChains(m.chains),
		counts:    cloneCounts(m.counts),
		traffic:   m.traffic.items(),
		leases:    m.leases.rows(),

		leaseCounts: m.leases.counts(),
		history:     len(m.traffic.buf),
		logs:        m.logs.items(),
		reqRate:     m.reqRate.series(now),
		errRate:     m.errRate.series(now),
		tot:         m.tot,
		paused:      m.paused,
		help:        m.help,
		focus:       m.focus,
		panes:       m.panes,
	}

	if m.paused {
		snap.traffic = slices.Clone(m.frozen)
	}

	return snap, true
}

// cloneChains copies the chains by value so the draw loop reads counters that
// cannot change under it.
func cloneChains(src map[events.Family][]*chainLink) map[events.Family][]chainLink {
	out := make(map[events.Family][]chainLink, len(src))

	for f, links := range src {
		copied := make([]chainLink, len(links))
		for i, l := range links {
			copied[i] = *l
			copied[i].args = slices.Clone(l.args)
		}

		out[f] = copied
	}

	return out
}

// cloneCounts copies the per-family counters, maps included.
func cloneCounts(src map[events.Family]*familyCounters) map[events.Family]familyCounters {
	out := make(map[events.Family]familyCounters, len(src))
	for f, c := range src {
		out[f] = c.clone()
	}

	return out
}

// setGeometry records where a pane's window ended up. The draw loop is the
// only place that knows a pane's height, and the scroll keys need it.
func (m *model) setGeometry(id paneID, start, total, height int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := &m.panes[id]
	v.start, v.total, v.height = start, total, height
}
