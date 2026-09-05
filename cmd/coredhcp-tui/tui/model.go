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

// Hostnames, client identifiers and error texts come off the wire, so they are
// cut down before they are stored, not only before they are drawn.
const (
	maxIDLen    = 64
	maxNameLen  = 48
	maxErrLen   = 160
	maxWordLen  = 24
	maxAddrs    = 4
	maxFamilies = 8
	maxTypeKeys = 16
)

// One minute, which is also the window the status line grades on.
const rateBuckets = 60

const pathCount = 4

// Any other family is still counted, it just has no section of its own.
var renderFamilies = []events.Family{events.FamilyV4, events.FamilyV6}

// The declaration order is the order Tab walks.
type paneID int

const (
	paneTraffic paneID = iota
	paneLeases
	panePlugins
	paneLog
	paneCount
)

func (p paneID) follows() bool { return p == paneTraffic || p == paneLog }

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

// offset is where the operator put the window; start, total and height are
// written back by the draw loop, so the keys move relative to what is onscreen.
type paneView struct {
	offset int
	follow bool
	start  int
	total  int
	height int
}

// Fixed size, so the traffic and log panes do not grow with uptime.
type ring[T any] struct {
	buf   []T
	start int
	n     int
}

func newRing[T any](capacity int) *ring[T] {
	return &ring[T]{buf: make([]T, max(capacity, 1))}
}

func (r *ring[T]) push(v T) {
	if r.n < len(r.buf) {
		r.buf[(r.start+r.n)%len(r.buf)] = v
		r.n++

		return
	}

	r.buf[r.start] = v
	r.start = (r.start + 1) % len(r.buf)
}

func (r *ring[T]) items() []T {
	out := make([]T, r.n)
	for i := range out {
		out[i] = r.buf[(r.start+i)%len(r.buf)]
	}

	return out
}

func (r *ring[T]) reset() {
	clear(r.buf)
	r.start, r.n = 0, 0
}

// One-second buckets. Advancing zeroes the buckets it skipped, so an idle
// minute reads as zeroes rather than as stale peaks.
type rateRing struct {
	buckets [rateBuckets]uint32
	sec     int64
	head    int
	primed  bool
}

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

// An event stamped before the head second lands in the head bucket: only a
// clock step back does that, and losing a second beats rewriting history.
func (r *rateRing) add(at time.Time) {
	r.advance(at)
	r.buckets[r.head]++
}

func (r *rateRing) series(now time.Time) []uint32 {
	r.advance(now)

	out := make([]uint32, rateBuckets)
	for i := range out {
		out[i] = r.buckets[(r.head+1+i)%rateBuckets]
	}

	return out
}

func (r *rateRing) reset() {
	r.buckets = [rateBuckets]uint32{}
}

func sum(values []uint32) uint64 {
	var total uint64
	for _, v := range values {
		total += uint64(v)
	}

	return total
}

func peak(values []uint32) uint32 {
	var top uint32
	for _, v := range values {
		top = max(top, v)
	}

	return top
}

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

func newFamilyCounters() *familyCounters {
	return &familyCounters{in: map[string]uint64{}, out: map[string]uint64{}}
}

// A deep copy, so the draw loop can read the counters outside the lock.
func (c *familyCounters) clone() familyCounters {
	out := *c
	out.in = maps.Clone(c.in)
	out.out = maps.Clone(c.out)

	return out
}

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
		// Neither is a problem, and the type is already in the in map.
	}
}

// Capped: a packet the library could not name must not grow the map without bound.
func bumpKey(m map[string]uint64, key string) {
	if key == "" {
		key = "?"
	}

	if _, known := m[key]; !known && len(m) >= maxTypeKeys {
		key = "other"
	}

	m[key]++
}

type chainLink struct {
	name    string
	args    []string
	reached uint64
	replied uint64
	dropped uint64
}

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

// Guarded by one mutex: the observer methods write it from the server's packet
// goroutines, the draw loop reads it once per frame through snapshot.
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

// Taken under a single lock, so a frame cannot show one pane's state next to
// another pane's.
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

	// leaseCounts covers the whole table, which is more than the rows above.
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

func (m *model) addListener(l events.Listener) {
	l.Address, _ = clip(l.Address, maxNameLen)
	l.Interface, _ = clip(l.Interface, maxWordLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.listeners = append(m.listeners, l)
	m.dirty = true
}

// The server calls this in chain order, which is what gives a link its position.
func (m *model) addPlugin(p events.Plugin) {
	link := &chainLink{name: p.Name, args: slices.Clone(p.Args)}
	link.name, _ = clip(link.name, maxWordLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.chains[p.Family] = append(m.chains[p.Family], link)
	m.dirty = true
}

// Runs on the server's packet path, so it allocates as little as it can and
// never formats anything.
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

// Bounds the ring's memory by its length rather than by what a client put in a
// hostname option.
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

// The map is capped: Family is a byte, and events does not promise it is one of two.
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

// Caller holds the lock.
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
		// Neither dropped nor errored, so no counter and no timestamp moves.
	}
}

// The event names only the link that stopped the chain; with one at position p,
// links 1..p ran, and with none every plugin did. Caller holds the lock.
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
		// The chain stopped here, but nothing was sent and nothing dropped.
	case events.OutcomeParseError, events.OutcomeUnsupported:
	}
}

func (m *model) addLog(now time.Time, raw string) {
	raw, _ = clip(raw, maxLogLineLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logs.push(logEntry{at: now, raw: raw})
	m.dirty = true
}

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

// By value, so the draw loop reads counters that cannot change under it.
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

func cloneCounts(src map[events.Family]*familyCounters) map[events.Family]familyCounters {
	out := make(map[events.Family]familyCounters, len(src))
	for f, c := range src {
		out[f] = c.clone()
	}

	return out
}

// The draw loop is the only place that knows a pane's height, and the scroll
// keys need it.
func (m *model) setGeometry(id paneID, start, total, height int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := &m.panes[id]
	v.start, v.total, v.height = start, total, height
}
