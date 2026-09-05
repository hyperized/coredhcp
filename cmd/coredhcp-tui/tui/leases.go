// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coredhcp/coredhcp/events"
)

// The table holds up to WithMaxLeases entries, but rows are sorted by last
// seen, so copying the newest few hundred per frame keeps the frame cost flat.
const leaseSnapshotRows = 500

type leaseState uint8

// Read out of the traffic, not out of a plugin's lease database. An entry
// moves on to confirmed while the header's issued total keeps the offer.
const (
	leaseNone leaseState = iota
	leaseOffered
	leaseConfirmed
	leaseRefused
	leaseReleased
	leaseDeclined
	leaseStateCount
)

func (s leaseState) label() string {
	switch s {
	case leaseOffered:
		return "offered"
	case leaseConfirmed:
		return "confirmed"
	case leaseRefused:
		return "refused"
	case leaseReleased:
		return "released"
	case leaseDeclined:
		return "declined"
	case leaseNone, leaseStateCount:
	}

	return "-"
}

func (s leaseState) tag() string {
	switch s {
	case leaseOffered:
		return tagWarn
	case leaseConfirmed:
		return tagGood
	case leaseRefused, leaseDeclined:
		return tagBad
	case leaseReleased, leaseNone, leaseStateCount:
	}

	return tagDim
}

type leaseKey struct {
	family events.Family
	client string
}

// The list is intrusive so touching an entry and evicting the oldest are both
// constant time.
type leaseEntry struct {
	prev, next *leaseEntry

	key      leaseKey
	hostname string
	addrs    []netip.Prefix
	plugin   string
	state    leaseState
	seen     time.Time
	expiry   time.Time
}

type leaseRow struct {
	family   events.Family
	client   string
	hostname string
	addrs    []netip.Prefix
	plugin   string
	state    leaseState
	seen     time.Time
	expiry   time.Time
}

// Bounded at max entries, so a client flooding the server with new identifiers
// cannot grow it without limit.
type leaseTable struct {
	max        int
	idx        map[leaseKey]*leaseEntry
	head, tail *leaseEntry
	states     [leaseStateCount]int
}

func newLeaseTable(maxEntries int) *leaseTable {
	return &leaseTable{max: max(maxEntries, 1), idx: map[leaseKey]*leaseEntry{}}
}

func (t *leaseTable) update(r events.Request, state leaseState) {
	key := leaseKey{family: r.Family, client: r.ClientID}

	e, ok := t.idx[key]
	if ok {
		t.unlink(e)
		t.states[e.state]--
	} else {
		t.evict()

		e = &leaseEntry{key: key}
		t.idx[key] = e
	}

	t.pushFront(e)
	t.states[state]++

	e.state = state
	e.seen = r.Time

	if r.Hostname != "" {
		e.hostname = r.Hostname
	}

	if len(r.Addresses) > 0 {
		e.addrs = r.Addresses
	}

	if r.Plugin != "" {
		e.plugin = r.Plugin
	}

	// When an ACK omits the lease time, the deadline the OFFER carried is still
	// the best we know.
	if exp := expiryFor(r, state); !exp.IsZero() {
		e.expiry = exp
	} else if state != leaseOffered && state != leaseConfirmed {
		e.expiry = time.Time{}
	}
}

// Released, refused and declined have no address to count down, so they clear it.
func expiryFor(r events.Request, state leaseState) time.Time {
	if state != leaseOffered && state != leaseConfirmed {
		return time.Time{}
	}

	if r.LeaseTime <= 0 {
		return time.Time{}
	}

	return r.Time.Add(r.LeaseTime)
}

func (t *leaseTable) rows() []leaseRow {
	out := make([]leaseRow, 0, min(len(t.idx), leaseSnapshotRows))

	for e := t.head; e != nil && len(out) < leaseSnapshotRows; e = e.next {
		out = append(out, leaseRow{
			family:   e.key.family,
			client:   e.key.client,
			hostname: e.hostname,
			addrs:    e.addrs,
			plugin:   e.plugin,
			state:    e.state,
			seen:     e.seen,
			expiry:   e.expiry,
		})
	}

	return out
}

func (t *leaseTable) counts() [leaseStateCount]int { return t.states }

func (t *leaseTable) evict() {
	if len(t.idx) < t.max || t.tail == nil {
		return
	}

	e := t.tail
	t.unlink(e)
	t.states[e.state]--
	delete(t.idx, e.key)
}

func (t *leaseTable) pushFront(e *leaseEntry) {
	e.prev, e.next = nil, t.head

	if t.head != nil {
		t.head.prev = e
	}

	t.head = e
	if t.tail == nil {
		t.tail = e
	}
}

func (t *leaseTable) unlink(e *leaseEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if t.head == e {
		t.head = e.next
	}

	if e.next != nil {
		e.next.prev = e.prev
	} else if t.tail == e {
		t.tail = e.prev
	}

	e.prev, e.next = nil, nil
}

// Caller holds the model lock.
func (m *model) recordLease(r events.Request) {
	state := leaseTransition(r)
	if state == leaseNone || r.ClientID == "" {
		return
	}

	// The totals count for the lifetime of the process; the table holds one
	// state per client.
	switch state {
	case leaseOffered:
		m.tot.issued++
	case leaseConfirmed:
		m.tot.confirmed++
	case leaseNone, leaseRefused, leaseReleased, leaseDeclined, leaseStateCount:
	}

	m.leases.update(r, state)
}

func leaseTransition(r events.Request) leaseState {
	switch r.Family {
	case events.FamilyV4:
		return leaseTransitionV4(r)
	case events.FamilyV6:
		return leaseTransitionV6(r)
	}

	return leaseNone
}

// RELEASE and DECLINE get no answer, so there is no reply to read the outcome
// off: RELEASE counts either way, DECLINE once the chain has seen it.
func leaseTransitionV4(r events.Request) leaseState {
	typ, reply := strings.ToUpper(r.Type), strings.ToUpper(r.ReplyType)

	switch typ {
	case "RELEASE":
		return leaseReleased
	case "DECLINE":
		if r.Outcome == events.OutcomeNoReply {
			return leaseDeclined
		}

		return leaseNone
	}

	if r.Outcome != events.OutcomeReplied {
		return leaseNone
	}

	switch {
	case typ == "DISCOVER" && reply == "OFFER":
		return leaseOffered
	case typ == "REQUEST" && reply == "ACK" && len(r.Addresses) > 0:
		return leaseConfirmed
	case typ == "REQUEST" && reply == "NAK":
		return leaseRefused
	}

	return leaseNone
}

// A REPLY carrying no addresses is the server saying no, which is the closest
// v6 has to a NAK.
func leaseTransitionV6(r events.Request) leaseState {
	typ, reply := strings.ToUpper(r.Type), strings.ToUpper(r.ReplyType)

	if typ == "RELEASE" {
		return leaseReleased
	}

	if r.Outcome != events.OutcomeReplied {
		return leaseNone
	}

	switch typ {
	case "SOLICIT":
		return solicitState(reply)
	case "REQUEST", "RENEW", "REBIND":
		if reply == "REPLY" {
			if len(r.Addresses) > 0 {
				return leaseConfirmed
			}

			return leaseRefused
		}
	case "CONFIRM":
		if reply == "REPLY" && len(r.Addresses) > 0 {
			return leaseConfirmed
		}
	}

	return leaseNone
}

// A REPLY to a SOLICIT is rapid commit: the address arrived in one round trip.
func solicitState(reply string) leaseState {
	switch reply {
	case "ADVERTISE":
		return leaseOffered
	case "REPLY":
		return leaseConfirmed
	}

	return leaseNone
}

const (
	leaseClientW    = 20
	leaseAddrW      = 24
	leaseStateW     = 9
	leaseTimeW      = 8
	leaseSeenW      = 9
	leasePluginW    = 10
	leaseMinClientW = 8
	leaseMinAddrW   = 8
)

// A zero width means the column is dropped rather than narrowed.
type leaseCols struct {
	client, addr, state, lease, seen, plugin int
}

func (c leaseCols) width() int {
	total, gaps := 0, -1

	for _, w := range []int{c.client, c.addr, c.state, c.lease, c.seen, c.plugin} {
		if w > 0 {
			total += w
			gaps++
		}
	}

	return total + max(gaps, 0)
}

// Starts from the floors and hands the leftovers to client and address, the two
// that hold something worth reading in full.
func leaseColumns(width int) leaseCols {
	c := leaseCols{
		client: leaseMinClientW, addr: leaseMinAddrW, state: leaseStateW,
		lease: leaseTimeW, seen: leaseSeenW, plugin: leasePluginW,
	}

	for _, col := range []*int{&c.plugin, &c.lease, &c.seen} {
		if c.width() <= width {
			break
		}

		*col = 0
	}

	grow(&c.client, leaseClientW, width-c.width())
	grow(&c.addr, leaseAddrW, width-c.width())
	grow(&c.addr, width, width-c.width())

	return c
}

func grow(field *int, ceiling, spare int) {
	if spare <= 0 {
		return
	}

	*field += min(spare, max(ceiling-*field, 0))
}

// Titles are ASCII: see newPane for why.
func leaseTitle(s snapshot) string {
	counts := s.leaseCounts

	return " leases (" + strconv.Itoa(counts[leaseOffered]) + " offered, " +
		strconv.Itoa(counts[leaseConfirmed]) + " confirmed) "
}

// The header row is this same shape, so both go through one writer and cannot
// drift apart when a column is dropped.
type leaseCells struct {
	client, host, addr, state, lease, seen, plugin string
	clientTag, stateTag, leaseTag                  string
}

// The first line is the column header, which the draw loop keeps in place.
func leaseLines(s snapshot, width int) []string {
	cols := leaseColumns(width)

	lines := make([]string, 0, len(s.leases)+2)
	lines = append(lines, writeLease(width, cols, leaseCells{
		client: "client", addr: "address", state: "state", lease: "lease",
		seen: "seen", plugin: "plugin",
		clientTag: tagDim, stateTag: tagDim, leaseTag: tagDim,
	}))

	if len(s.leases) == 0 {
		return append(lines, newDim(width, "no leases seen yet"))
	}

	for _, row := range s.leases {
		lines = append(lines, writeLease(width, cols, leaseRowCells(s.now, row)))
	}

	return lines
}

func leaseRowCells(now time.Time, row leaseRow) leaseCells {
	return leaseCells{
		client:    row.client,
		host:      row.hostname,
		addr:      joinAddrs(row.addrs),
		state:     row.state.label(),
		lease:     humanRemaining(now, row.expiry),
		seen:      humanSince(now, row.seen),
		plugin:    row.plugin,
		clientTag: tagPlain,
		stateTag:  row.state.tag(),
		leaseTag:  leaseTimeTag(now, row),
	}
}

func writeLease(width int, cols leaseCols, cells leaseCells) string {
	l := newLine(width)

	l.cell(cols.client, func(b *lineBuf) {
		b.tail(cells.clientTag, cells.client)

		if cells.host != "" && b.room() > 1 {
			b.space(1)
			b.text(tagDim, cells.host)
		}
	})
	l.space(1)
	l.col(tagPlain, cells.addr, cols.addr)
	l.space(1)
	l.col(cells.stateTag, cells.state, cols.state)

	for _, col := range []struct {
		width int
		tag   string
		text  string
	}{
		{cols.lease, cells.leaseTag, cells.lease},
		{cols.seen, tagDim, cells.seen},
		{cols.plugin, tagDim, cells.plugin},
	} {
		if col.width == 0 {
			continue
		}

		l.space(1)
		l.col(col.tag, col.text, col.width)
	}

	return l.String()
}

func leaseTimeTag(now time.Time, row leaseRow) string {
	if row.expiry.IsZero() || !row.expiry.After(now) {
		return tagDim
	}

	return tagPlain
}

func newDim(width int, text string) string {
	l := newLine(width)
	l.text(tagDim, text)

	return l.String()
}
