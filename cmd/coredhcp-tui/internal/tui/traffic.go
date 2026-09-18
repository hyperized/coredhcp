// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"strconv"
	"strings"

	"github.com/coredhcp/coredhcp/events"
)

// Preferred widths of the traffic columns, and the floors the two that hold
// wire data are allowed to shrink to. The reply column has to hold ADVERTISE,
// so the error outcomes are shortened to fit next to it: the full reason
// follows on the same row anyway.
const (
	trafficTimeW      = 12
	trafficShortT     = 8
	trafficFamW       = 2
	trafficIfaceW     = 5
	trafficTypeW      = 9
	trafficReplyW     = 9
	trafficClientW    = 17
	trafficAddrW      = 15
	trafficPluginW    = 10
	trafficPathW      = 9
	trafficDurW       = 7
	trafficMinClient  = 10
	trafficMinAddr    = 8
	trafficWideClient = 26
	trafficWideAddr   = 40
)

// trafficCols is how wide each column is on this terminal. A zero width means
// the column is not shown: a narrow pane gives up the columns an operator can
// live without before it starts cutting into the addresses.
type trafficCols struct {
	time, fam, iface, typ, reply, client, addr, plugin, path, dur int
}

// width is what the row costs, single spaces between columns included. The
// arrow between the request and the reply is always there.
func (c trafficCols) width() int {
	total, gaps := 0, -1

	for _, w := range []int{c.time, c.fam, c.iface, c.typ, 1, c.reply, c.client, c.addr, c.plugin, c.path, c.dur} {
		if w > 0 {
			total += w
			gaps++
		}
	}

	return total + max(gaps, 0)
}

// trafficColumns fits the columns into width. The reply path and the chain
// duration go first because the counters pane already has them in aggregate,
// then the interface, then the plugin; after that the timestamp loses its
// milliseconds and only then do the address and client columns give ground.
func trafficColumns(width int) trafficCols {
	c := trafficCols{
		time: trafficTimeW, fam: trafficFamW, iface: trafficIfaceW, typ: trafficTypeW,
		reply: trafficReplyW, client: trafficClientW, addr: trafficAddrW,
		plugin: trafficPluginW, path: trafficPathW, dur: trafficDurW,
	}

	for _, col := range []*int{&c.path, &c.dur, &c.iface, &c.plugin} {
		if c.width() <= width {
			break
		}

		*col = 0
	}

	if c.width() > width {
		c.time = trafficShortT
	}

	shrink(&c.addr, trafficMinAddr, c.width()-width)
	shrink(&c.client, trafficMinClient, c.width()-width)

	return fillTraffic(c, width)
}

// fillTraffic spends whatever room is left over: first by bringing back the
// columns that were dropped, most useful first, then by widening the client
// and address columns, which is where a wide terminal earns its keep.
func fillTraffic(c trafficCols, width int) trafficCols {
	for _, col := range []struct {
		field *int
		want  int
	}{
		{&c.plugin, trafficPluginW},
		{&c.iface, trafficIfaceW},
		{&c.dur, trafficDurW},
		{&c.path, trafficPathW},
	} {
		if *col.field == 0 && width-c.width() > col.want {
			*col.field = col.want
		}
	}

	grow(&c.client, trafficWideClient, width-c.width())
	grow(&c.addr, trafficWideAddr, width-c.width())

	return c
}

// shrink takes up to over columns off a field, never below floor.
func shrink(field *int, floor, over int) {
	if over <= 0 {
		return
	}

	*field -= min(over, max(*field-floor, 0))
}

// replyTags grades the reply that went out. Anything that hands a client an
// address or an answer is good; a NAK is the server saying no.
var replyTags = map[string]string{
	"OFFER":     tagGood,
	"ACK":       tagGood,
	"ADVERTISE": tagGood,
	"REPLY":     tagGood,
	"NAK":       tagWarn,
}

// familyShort is the two character family marker in the traffic pane.
func familyShort(f events.Family) string {
	switch f {
	case events.FamilyV4:
		return "v4"
	case events.FamilyV6:
		return "v6"
	}

	return "v?"
}

// outcomeWord is what the reply column says about a request, and how it is
// graded.
func outcomeWord(r events.Request) (tag, word string) {
	switch r.Outcome {
	case events.OutcomeReplied:
		reply := strings.ToUpper(r.ReplyType)
		if t, ok := replyTags[reply]; ok {
			return t, r.ReplyType
		}

		return tagPlain, r.ReplyType
	case events.OutcomeDropped:
		return tagWarn, "drop"
	case events.OutcomeNoReply:
		return tagDim, "no reply"
	case events.OutcomeParseError:
		return tagBad, "parse"
	case events.OutcomeUnsupported:
		return tagBad, "unsup"
	case events.OutcomeSendError:
		return tagBad, "send"
	}

	return tagDim, "?"
}

// trafficTitle names the pane, says how much history it keeps and whether the
// operator froze it. Titles are ASCII: see newPane for why.
func trafficTitle(s snapshot) string {
	if s.paused {
		return " traffic (last " + strconv.Itoa(s.history) + ", paused) "
	}

	return " traffic (last " + strconv.Itoa(s.history) + ") "
}

// trafficLines renders the traffic ring, oldest first, one row per request.
func trafficLines(s snapshot, width int) []string {
	if len(s.traffic) == 0 {
		return []string{newDim(width, "waiting for the first request")}
	}

	lines := make([]string, 0, len(s.traffic))
	for i := range s.traffic {
		lines = append(lines, trafficLine(s.traffic[i], width))
	}

	return lines
}

// trafficLine renders one request: when it arrived, what came in, what went
// out and who decided that. Rows that ended in an error give up the path and
// duration columns to say what went wrong instead.
func trafficLine(r events.Request, width int) string {
	cols := trafficColumns(width)
	stamp := "15:04:05.000"

	if cols.time == trafficShortT {
		stamp = "15:04:05"
	}

	l := newLine(width)
	l.col(tagDim, r.Time.Format(stamp), cols.time)
	l.space(1)
	l.col(tagPlain, familyShort(r.Family), cols.fam)

	if cols.iface > 0 {
		l.space(1)
		l.col(tagDim, r.Interface, cols.iface)
	}

	l.space(1)
	l.col(tagPlain, r.Type, cols.typ)
	l.space(1)
	l.text(tagDim, "\u2192")
	l.space(1)

	tag, word := outcomeWord(r)
	l.col(tag, word, cols.reply)

	// A packet that never parsed has no client and no address, so the reason
	// it failed gets those columns instead of padding them out.
	if r.Error != "" && r.ClientID == "" && len(r.Addresses) == 0 {
		l.space(1)
		l.text(tagDim, r.Error)

		return l.String()
	}

	l.space(1)
	l.cell(cols.client, func(b *lineBuf) {
		b.tail(tagPlain, r.ClientID)

		if r.Hostname != "" && b.room() > 1 {
			b.space(1)
			b.text(tagDim, r.Hostname)
		}
	})
	l.space(1)
	l.col(tagPlain, joinAddrs(r.Addresses), cols.addr)

	if cols.plugin > 0 {
		l.space(1)
		l.col(tagDim, r.Plugin, cols.plugin)
	}

	if r.Error != "" {
		l.space(1)
		l.text(tagDim, r.Error)

		return l.String()
	}

	if cols.path > 0 {
		l.space(1)
		l.col(tagDim, r.Path.String(), cols.path)
	}

	if cols.dur > 0 {
		l.space(1)
		l.colRight(tagDim, humanDuration(r.Duration), cols.dur)
	}

	return l.String()
}
