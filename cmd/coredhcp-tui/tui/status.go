// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"strconv"
	"strings"
	"time"
)

// errorWindow is how far back the status line looks for trouble. A minute is
// long enough that a failure stays on screen while the operator reads it, and
// short enough that a fixed problem clears itself.
const errorWindow = time.Minute

// rateWindow is how many of the per-second buckets the header averages for
// its requests-per-second figure. Ten seconds tracks a burst without jumping
// around between frames.
const rateWindow = 10

// headerLine is the top row: who we are, how long we have been up, and the
// running totals.
func headerLine(s snapshot, width int) string {
	l := newLine(width)
	l.text(tagBold, "coredhcp")
	l.space(1)
	l.text(tagDim, s.version)
	l.space(2)
	l.text(tagPlain, "up "+humanUptime(s.uptime))
	l.space(2)
	l.text(tagPlain, "listeners="+strconv.Itoa(len(s.listeners)))
	l.space(2)
	l.text(tagPlain, "req="+humanCount(s.tot.requests))
	l.text(tagDim, " ("+recentRate(s.reqRate)+"/s)")
	l.space(2)
	l.text(tagPlain, "issued="+humanCount(s.tot.issued))
	l.space(1)
	l.text(tagPlain, "confirmed="+humanCount(s.tot.confirmed))
	l.space(1)
	l.text(countTag(s.tot.dropped, tagWarn), "dropped="+humanCount(s.tot.dropped))
	l.space(1)
	l.text(countTag(s.tot.errors, tagBad), "errors="+humanCount(s.tot.errors))

	return l.String()
}

// countTag colours a counter only once it has something to say.
func countTag(n uint64, tag string) string {
	if n == 0 {
		return tagPlain
	}

	return tag
}

// recentRate is the mean requests per second over the last rateWindow
// seconds, formatted with one decimal.
func recentRate(series []uint32) string {
	if len(series) == 0 {
		return "0.0"
	}

	window := series
	if len(window) > rateWindow {
		window = window[len(window)-rateWindow:]
	}

	return strconv.FormatFloat(float64(sum(window))/float64(len(window)), 'f', 1, 64)
}

// health is the graded state of the server plus the sentence that explains
// how it was graded.
type health struct {
	tag   string
	label string
	note  string
}

// grade reads the server's state the way an operator would: nothing to listen
// on is the worst case, then replies that could not be sent, then packets the
// server could not use, then a server that simply has not been asked anything
// yet.
func grade(s snapshot) health {
	switch {
	case len(s.listeners) == 0:
		return health{tag: tagBad, label: "FAILING", note: "no listeners bound"}
	case within(s.now, s.tot.lastSendErr):
		return health{
			tag:   tagBad,
			label: "FAILING",
			note:  listenerNote(s) + ", replies failed to send in the last minute",
		}
	case within(s.now, s.tot.lastSoftErr):
		return health{
			tag:   tagWarn,
			label: "DEGRADED",
			note:  listenerNote(s) + ", packets the server could not use in the last minute",
		}
	case s.tot.requests == 0:
		return health{tag: tagDim, label: "IDLE", note: listenerNote(s) + ", no requests yet"}
	}

	return health{
		tag:   tagGood,
		label: "HEALTHY",
		note:  listenerNote(s) + requestNote(s) + ", no errors in the last minute",
	}
}

// within reports whether t happened inside the grading window.
func within(now, t time.Time) bool {
	return !t.IsZero() && now.Sub(t) < errorWindow
}

// listenerNote counts the bound sockets.
func listenerNote(s snapshot) string {
	if len(s.listeners) == 1 {
		return "1 listener"
	}

	return strconv.Itoa(len(s.listeners)) + " listeners"
}

// requestNote says when the last request came in.
func requestNote(s snapshot) string {
	if s.tot.lastRequest.IsZero() {
		return ", no requests yet"
	}

	return ", last request " + humanSince(s.now, s.tot.lastRequest)
}

// statusLine is the graded one-liner under the header.
func statusLine(s snapshot, width int) string {
	h := grade(s)

	l := newLine(width)
	l.text(tagDim, "status: ")
	l.text(h.tag+"::b", h.label)
	l.space(2)
	l.text(tagDim, h.note)

	return l.String()
}

// footerKeys is the key hint row, in the order the keys are worth learning.
var footerKeys = []struct{ key, what string }{
	{"q", "quit"},
	{"p", "pause"},
	{"tab", "focus"},
	{"↑↓", "scroll"},
	{"c", "clear"},
	{"?", "help"},
}

// footerLine renders the key hints, with the pause marker pushed to the right
// where it is hard to miss.
func footerLine(s snapshot, width int) string {
	l := newLine(width)

	for i, k := range footerKeys {
		if i > 0 {
			l.text(tagDim, " · ")
		}

		l.text(tagBold, k.key)
		l.text(tagDim, " "+k.what)
	}

	if s.paused {
		const mark = "PAUSED"

		l.space(max(l.room()-len(mark), 0))
		l.text(tagWarn, mark)
	}

	return l.String()
}

// helpLines is the text of the help overlay.
func helpLines() []string {
	return []string{
		"[" + tagBold + "]keys" + resetTag,
		"",
		"  q, Esc, Ctrl-C   quit",
		"  p                pause the traffic pane, collection continues",
		"  Tab, Shift-Tab   move focus between panes",
		"  1 2 3 4          focus traffic, leases, plugins, log",
		"  ↑ ↓ PgUp PgDn    scroll the focused pane",
		"  Home, End        jump to the oldest or newest row",
		"  c                clear traffic, counters and rate history",
		"  ?                close this help",
		"",
		"[" + tagDim + "]Leases are read out of the traffic, not out of a plugin's" + resetTag,
		"[" + tagDim + "]lease database: what was offered, acknowledged, refused" + resetTag,
		"[" + tagDim + "]or released is what the server saw on the wire. A lease" + resetTag,
		"[" + tagDim + "]sits at offered until the client comes back for it; the" + resetTag,
		"[" + tagDim + "]header's issued counts every offer since startup." + resetTag,
	}
}

// helpText is the overlay as one block, ready for a text view.
func helpText() string { return strings.Join(helpLines(), "\n") }
