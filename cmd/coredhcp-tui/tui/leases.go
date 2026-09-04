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

// leaseSnapshotRows bounds how much of the lease table one frame copies. The
// table itself holds up to WithMaxLeases entries; the pane is a view of what
// is happening now, sorted by last seen, so copying the newest few hundred per
// frame is enough to scroll through and keeps the frame cost flat.
const leaseSnapshotRows = 500

// leaseState is what the last request told us about a client's address.
type leaseState uint8

// The lease states, derived from traffic rather than from any plugin's lease
// database. leaseNone means the request said nothing about a lease.
//
// leaseOffered is an address the server put on the table and the client has
// not taken yet. The header's issued counter is the lifetime number of those
// offers, so the two numbers differ once a client accepts one: the offer is
// counted for good, the table entry moves on to confirmed.
const (
	leaseNone leaseState = iota
	leaseOffered
	leaseConfirmed
	leaseRefused
	leaseReleased
	leaseDeclined
	leaseStateCount
)

// label is the word shown in the state column.
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

// tag grades the state: an offer nobody has taken yet is attention, confirmed
// is good, refused and declined are errors, released is history.
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

// leaseKey identifies a client within its protocol family.
type leaseKey struct {
	family events.Family
	client string
}

// leaseEntry is one client's current lease state plus its place in the
// recently-seen list. The list is intrusive so that touching an entry, and
// evicting the least recently seen one, are both constant time.
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

// leaseRow is a lease copied out for rendering.
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

// leaseTable holds one entry per (family, client), ordered by when it was
// last seen, newest first. It is bounded: past max entries the least recently
// seen one is dropped, so a client that floods the server with new identifiers
// cannot grow it without limit.
type leaseTable struct {
	max        int
	idx        map[leaseKey]*leaseEntry
	head, tail *leaseEntry
	states     [leaseStateCount]int
}

// newLeaseTable returns an empty table holding at most max entries.
func newLeaseTable(maxEntries int) *leaseTable {
	return &leaseTable{max: max(maxEntries, 1), idx: map[leaseKey]*leaseEntry{}}
}

// update applies one request's lease meaning to the client's entry.
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

	// An ACK usually repeats the lease time, but when it does not the
	// deadline the OFFER carried is still the best we know.
	if exp := expiryFor(r, state); !exp.IsZero() {
		e.expiry = exp
	} else if state != leaseOffered && state != leaseConfirmed {
		e.expiry = time.Time{}
	}
}

// expiryFor is when the lease runs out, or the zero time when the request did
// not say. A lease that was released, refused or declined has no address to
// count down, so those states clear it.
func expiryFor(r events.Request, state leaseState) time.Time {
	if state != leaseOffered && state != leaseConfirmed {
		return time.Time{}
	}

	if r.LeaseTime <= 0 {
		return time.Time{}
	}

	return r.Time.Add(r.LeaseTime)
}

// rows copies the newest entries out for rendering.
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

// counts reports how many entries are in each state.
func (t *leaseTable) counts() [leaseStateCount]int { return t.states }

// evict drops the least recently seen entry when the table is full.
func (t *leaseTable) evict() {
	if len(t.idx) < t.max || t.tail == nil {
		return
	}

	e := t.tail
	t.unlink(e)
	t.states[e.state]--
	delete(t.idx, e.key)
}

// pushFront puts e at the recently-seen end of the list.
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

// unlink takes e out of the list, leaving it usable for pushFront.
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

// recordLease folds the request's lease meaning into the table and the
// issued / confirmed totals. Caller holds the model lock.
func (m *model) recordLease(r events.Request) {
	state := leaseTransition(r)
	if state == leaseNone || r.ClientID == "" {
		return
	}

	// The totals count offers and confirmations for the lifetime of the
	// process; the table holds one state per client, which is why an offer
	// stays in the total after the client's entry has moved to confirmed.
	switch state {
	case leaseOffered:
		m.tot.issued++
	case leaseConfirmed:
		m.tot.confirmed++
	case leaseNone, leaseRefused, leaseReleased, leaseDeclined, leaseStateCount:
	}

	m.leases.update(r, state)
}

// leaseTransition reads one request as a statement about the client's lease.
// The server does not tell us what a plugin wrote to its lease database, so
// this is the DHCP exchange itself: what was offered, what was acknowledged,
// what was refused and what the client gave back.
func leaseTransition(r events.Request) leaseState {
	switch r.Family {
	case events.FamilyV4:
		return leaseTransitionV4(r)
	case events.FamilyV6:
		return leaseTransitionV6(r)
	}

	return leaseNone
}

// leaseTransitionV4 reads a DHCPv4 exchange. RELEASE counts whatever the
// server did with it, because the client has already stopped using the
// address either way, and a DECLINE arrives as an unsupported message type
// since the server has no reply for it.
func leaseTransitionV4(r events.Request) leaseState {
	typ, reply := strings.ToUpper(r.Type), strings.ToUpper(r.ReplyType)

	switch typ {
	case "RELEASE":
		return leaseReleased
	case "DECLINE":
		if r.Outcome == events.OutcomeUnsupported {
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

// leaseTransitionV6 reads a DHCPv6 exchange. A REPLY with no addresses to a
// REQUEST, RENEW or REBIND is the server saying no, which is the closest v6
// has to a NAK. INFORMATION-REQUEST never carries a lease.
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

// solicitState splits the two answers to a SOLICIT: the usual ADVERTISE, and
// the REPLY a server sends when the client asked for rapid commit and got the
// address in one round trip.
func solicitState(reply string) leaseState {
	switch reply {
	case "ADVERTISE":
		return leaseOffered
	case "REPLY":
		return leaseConfirmed
	}

	return leaseNone
}

// Preferred widths of the lease columns, with floors for the two that hold
// wire data.
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

// leaseCols is how wide each column of the lease pane is on this terminal. A
// zero width means the column is not shown.
type leaseCols struct {
	client, addr, state, lease, seen, plugin int
}

// width is what a lease row costs, single spaces included.
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

// leaseColumns fits the lease columns into width. It starts from the floors,
// drops the columns an operator can do without in a narrow pane, and hands
// whatever is left over back to the address and client columns, which are the
// two that hold something worth reading in full.
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

// grow gives a column up to spare more columns, never past ceiling.
func grow(field *int, ceiling, spare int) {
	if spare <= 0 {
		return
	}

	*field += min(spare, max(ceiling-*field, 0))
}

// leaseTitle names the pane and carries the live state counts. Titles are
// ASCII: see newPane for why.
func leaseTitle(s snapshot) string {
	counts := s.leaseCounts

	return " leases (" + strconv.Itoa(counts[leaseOffered]) + " offered, " +
		strconv.Itoa(counts[leaseConfirmed]) + " confirmed) "
}

// leaseCells is one lease row's text, already graded. The header row is the
// same shape with the column names in it, so both go through one writer and
// cannot drift apart when a column is dropped.
type leaseCells struct {
	client, host, addr, state, lease, seen, plugin string
	clientTag, stateTag, leaseTag                  string
}

// leaseLines renders the lease pane. The first line is the column header and
// the draw loop keeps it in place while the rest scrolls.
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

// leaseRowCells turns one lease into the text of its row.
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

// writeLease lays one row out across the columns that survived.
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

// leaseTimeTag dims a lease whose time has run out, so an expired row reads as
// history next to the ones still counting down.
func leaseTimeTag(now time.Time, row leaseRow) string {
	if row.expiry.IsZero() || !row.expiry.After(now) {
		return tagDim
	}

	return tagPlain
}

// newDim is the one-line placeholder a pane shows when it has nothing yet.
func newDim(width int, text string) string {
	l := newLine(width)
	l.text(tagDim, text)

	return l.String()
}
