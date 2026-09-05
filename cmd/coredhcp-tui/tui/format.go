// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rivo/tview"
)

// The whole palette: a terminal that renders "gray" oddly costs us the dim text
// and nothing more.
const (
	tagGood  = "green"
	tagWarn  = "yellow"
	tagBad   = "red"
	tagDim   = "gray"
	tagBold  = "::b"
	tagPlain = ""
)

// tview's "[-]" resets the foreground only, which would leak bold into the rest
// of the row.
const resetTag = "[-:-:-]"

// Above this a rune stops being one cell wide, which the fixed columns assume.
// A width table would fix that at the price of a dependency no hostname needs.
const maxDisplayRune = 0x10ff

const ellipsis = '…'

// All one cell wide, so they pass the ceiling: it is about width, not provenance.
var uiGlyphs = map[rune]bool{
	'…': true, '→': true, '↑': true, '↓': true, '✓': true, '✗': true,
	'▁': true, '▂': true, '▃': true, '▄': true, '▅': true, '▆': true, '▇': true, '█': true,
}

// Everything written through it is sanitised and escaped, so a hostname or a
// plugin argument cannot smuggle tview markup or control characters onscreen.
type lineBuf struct {
	sb   strings.Builder
	left int
}

func newLine(width int) *lineBuf {
	return &lineBuf{left: max(width, 0)}
}

func (l *lineBuf) room() int { return l.left }

func (l *lineBuf) text(tag, s string) {
	l.emit(tag, s, l.left)
}

func (l *lineBuf) tail(tag, s string) {
	if l.left <= 0 {
		return
	}

	clipped, n := clipTail(s, l.left)
	l.emit(tag, clipped, n)
}

func (l *lineBuf) col(tag, s string, width int) {
	if width <= 0 || l.left <= 0 {
		return
	}

	room := min(width, l.left)
	used := l.emit(tag, s, room)
	l.space(room - used)
}

func (l *lineBuf) colRight(tag, s string, width int) {
	if width <= 0 || l.left <= 0 {
		return
	}

	room := min(width, l.left)
	clipped, n := clip(s, room)
	l.space(room - n)
	l.emit(tag, clipped, n)
}

func (l *lineBuf) space(n int) {
	n = min(n, l.left)
	if n <= 0 {
		return
	}

	l.sb.WriteString(strings.Repeat(" ", n))
	l.left -= n
}

// The single write path, which is what makes lineBuf's escaping total.
func (l *lineBuf) emit(tag, s string, limit int) int {
	limit = min(limit, l.left)
	if limit <= 0 || s == "" {
		return 0
	}

	clipped, n := clip(s, limit)

	if tag != tagPlain {
		l.sb.WriteByte('[')
		l.sb.WriteString(tag)
		l.sb.WriteByte(']')
	}

	l.sb.WriteString(tview.Escape(clipped))

	if tag != tagPlain {
		l.sb.WriteString(resetTag)
	}

	l.left -= n

	return n
}

// Trailing padding is kept so a short row cannot show the one underneath it.
func (l *lineBuf) String() string { return l.sb.String() }

// A negative limit means no limit, for sanitising alone. Reading stops once the
// budget is full, so a megabyte of hostname costs the budget, not the megabyte.
func clip(s string, limit int) (string, int) {
	if limit == 0 {
		return "", 0
	}

	runes := make([]rune, 0, min(len(s), 128))
	over := false

	for _, r := range s {
		if limit > 0 && len(runes) == limit {
			over = true

			break
		}

		runes = append(runes, printable(r))
	}

	if over {
		if limit == 1 {
			return string(ellipsis), 1
		}

		runes = append(runes[:limit-1], ellipsis)
	}

	return string(runes), len(runes)
}

// The end is the telling part of a MAC or a DUID, so the front is what goes.
// At most limit runes are read, so a long identifier costs the column, not the string.
func clipTail(s string, limit int) (string, int) {
	if limit <= 0 {
		return "", 0
	}

	runes := make([]rune, 0, limit)
	rest := s

	for rest != "" && len(runes) < limit {
		r, size := utf8.DecodeLastRuneInString(rest)
		rest = rest[:len(rest)-size]

		runes = append(runes, printable(r))
	}

	slices.Reverse(runes)

	if rest != "" {
		if limit == 1 {
			return string(ellipsis), 1
		}

		runes[0] = ellipsis
	}

	return string(runes), len(runes)
}

func printable(r rune) rune {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return ' '
	case uiGlyphs[r]:
		return r
	case r > maxDisplayRune, !unicode.IsPrint(r), unicode.IsMark(r):
		return '.'
	}

	return r
}

func humanCount(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}

	var b strings.Builder

	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
	}

	for i := head; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}

		b.WriteString(s[i : i+3])
	}

	return b.String()
}

// Three significant figures at most: 0.4ms against 2.1s, not six decimals of either.
func humanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Microsecond:
		return "<1µs"
	case d < time.Millisecond:
		return strconv.FormatFloat(float64(d)/float64(time.Microsecond), 'f', 0, 64) + "µs"
	case d < time.Second:
		return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 1, 64) + "ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m" + pad2(int(d/time.Second)%60) + "s"
	default:
		return strconv.Itoa(int(d/time.Hour)) + "h" + pad2(int(d/time.Minute)%60) + "m"
	}
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}

	return strconv.Itoa(n)
}

// Hours run past 24 rather than rolling over into days.
func humanUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	sec := int(d / time.Second)

	return pad2(sec/3600) + ":" + pad2(sec/60%60) + ":" + pad2(sec%60)
}

func humanSince(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	d := now.Sub(t)
	if d < time.Second {
		return "now"
	}

	return humanDuration(d) + " ago"
}

// A lease that ran out says so rather than counting up.
func humanRemaining(now, expiry time.Time) string {
	if expiry.IsZero() {
		return "-"
	}

	if !expiry.After(now) {
		return "expired"
	}

	return humanDuration(expiry.Sub(now))
}

func addrText(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}

	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}

	return p.String()
}

// A DHCPv6 reply can carry an IA_NA and several prefixes; past a handful the
// count is more use than the addresses.
const maxShownAddrs = 3

func joinAddrs(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return ""
	}

	shown := min(len(ps), maxShownAddrs)
	parts := make([]string, 0, shown+1)

	for _, p := range ps[:shown] {
		if t := addrText(p); t != "" {
			parts = append(parts, t)
		}
	}

	if len(ps) > shown {
		parts = append(parts, "+"+strconv.Itoa(len(ps)-shown))
	}

	return strings.Join(parts, ",")
}

var sparkRunes = [...]rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// A non-zero value never renders as the empty step, so a single request in a
// quiet minute is still visible.
func sparkline(values []uint32, peak uint32, width int) string {
	if width <= 0 || len(values) == 0 {
		return ""
	}

	if len(values) > width {
		values = values[len(values)-width:]
	}

	var b strings.Builder

	for _, v := range values {
		b.WriteRune(sparkRune(v, peak))
	}

	return b.String()
}

func sparkRune(v, peak uint32) rune {
	steps := uint64(len(sparkRunes) - 1)
	if v == 0 || peak == 0 {
		return sparkRunes[0]
	}

	idx := (uint64(v)*steps + uint64(peak) - 1) / uint64(peak)

	return sparkRunes[min(idx, steps)]
}

// The start index goes back to the model so the scroll keys can move relative to it.
func visible(lines []string, height, offset int, follow bool) ([]string, int) {
	if height <= 0 || len(lines) == 0 {
		return nil, 0
	}

	last := max(len(lines)-height, 0)

	start := offset
	if follow {
		start = last
	}

	start = min(max(start, 0), last)

	return lines[start:min(start+height, len(lines))], start
}

// Whatever budget the callback leaves is padded out, so a column built from a
// client id and a dim hostname still lines up with its neighbours.
func (l *lineBuf) cell(width int, write func(b *lineBuf)) {
	if width <= 0 || l.left <= 0 {
		return
	}

	room := min(width, l.left)
	sub := &lineBuf{left: room}

	write(sub)

	l.sb.WriteString(sub.String())

	used := room - sub.left
	l.left -= used

	l.space(room - used)
}
