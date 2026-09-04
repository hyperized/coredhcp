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

// Colour tags handed to tview's markup. They are the whole palette: the panes
// grade with them and nothing else, so a terminal that renders "gray" oddly
// only costs us the dim text.
const (
	tagGood  = "green"
	tagWarn  = "yellow"
	tagBad   = "red"
	tagDim   = "gray"
	tagBold  = "::b"
	tagPlain = ""
)

// resetTag closes every attribute a tag could have opened. tview's "[-]"
// resets the foreground only, which would leak bold into the rest of the row.
const resetTag = "[-:-:-]"

// maxDisplayRune is the highest rune we print as itself. Everything above it
// is replaced with a dot: the panes lay out in fixed columns and we count a
// rune as one cell, which stops being true around the East Asian blocks. A
// width table would fix that at the price of another dependency, and no DHCP
// hostname needs one.
const maxDisplayRune = 0x10ff

// ellipsis marks a value the column was too narrow for.
const ellipsis = '…'

// uiGlyphs are the characters the panes draw themselves that sit above
// maxDisplayRune. They are all one cell wide, so letting them through does not
// break a column: the point of the ceiling is width, not provenance.
var uiGlyphs = map[rune]bool{
	'…': true, '→': true, '↑': true, '↓': true, '✓': true, '✗': true,
	'▁': true, '▂': true, '▃': true, '▄': true, '▅': true, '▆': true, '▇': true, '█': true,
}

// lineBuf builds one pane row within a column budget. Every string written
// through it is sanitised and escaped, so a hostname or a plugin argument
// cannot smuggle tview markup or control characters onto the screen, and no
// row can push past the width it was given.
type lineBuf struct {
	sb   strings.Builder
	left int
}

// newLine starts a row that may use at most width columns.
func newLine(width int) *lineBuf {
	return &lineBuf{left: max(width, 0)}
}

// left reports how many columns are still free.
func (l *lineBuf) room() int { return l.left }

// text writes s in the given tag, truncated to whatever room is left. Pass
// tagPlain for the terminal's default colour.
func (l *lineBuf) text(tag, s string) {
	l.emit(tag, s, l.left)
}

// tail writes an identifier, keeping its end when it does not fit.
func (l *lineBuf) tail(tag, s string) {
	if l.left <= 0 {
		return
	}

	clipped, n := clipTail(s, l.left)
	l.emit(tag, clipped, n)
}

// col writes s in a column exactly width wide, padded with spaces. A value
// that does not fit ends in an ellipsis. When fewer than width columns are
// left the column is cut short and no padding follows it.
func (l *lineBuf) col(tag, s string, width int) {
	if width <= 0 || l.left <= 0 {
		return
	}

	room := min(width, l.left)
	used := l.emit(tag, s, room)
	l.space(room - used)
}

// colRight is col with the value pushed against the column's right edge, for
// numbers.
func (l *lineBuf) colRight(tag, s string, width int) {
	if width <= 0 || l.left <= 0 {
		return
	}

	room := min(width, l.left)
	clipped, n := clip(s, room)
	l.space(room - n)
	l.emit(tag, clipped, n)
}

// space writes n spaces, or as many as still fit.
func (l *lineBuf) space(n int) {
	n = min(n, l.left)
	if n <= 0 {
		return
	}

	l.sb.WriteString(strings.Repeat(" ", n))
	l.left -= n
}

// emit is the single write path: clip to limit, escape, wrap in the tag.
// Returns the columns consumed.
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

// String returns the finished row. Trailing padding is kept: it costs
// nothing and stops a shorter row from showing the one underneath it.
func (l *lineBuf) String() string { return l.sb.String() }

// clip returns s with every rune we refuse to print replaced, cut to at most
// limit columns, plus the number of columns the result takes. A negative
// limit means "no limit", which is only useful for sanitising. Truncation
// stops reading the input as soon as the budget is full, so a megabyte of
// hostname costs us the budget and not the megabyte.
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

// clipTail is clip for a value whose end is the part that tells it apart: the
// last octets of a MAC, or the link-layer address at the end of a DUID. It
// drops the front and puts the mark there, and it reads at most limit runes,
// so a long identifier costs the column and not the string.
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

// printable maps one rune to something safe to put in a cell.
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

// humanCount formats a counter with thousands separators.
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

// Durations are shown at three significant figures at most: the operator
// wants to see 0.4ms against 2.1s, not six decimals of either.
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

// pad2 zero-pads a number below 100 to two digits.
func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}

	return strconv.Itoa(n)
}

// humanUptime formats a running time as hh:mm:ss, with the hours allowed to
// run past 24 rather than rolling over into days.
func humanUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	sec := int(d / time.Second)

	return pad2(sec/3600) + ":" + pad2(sec/60%60) + ":" + pad2(sec%60)
}

// humanSince renders how long ago t was, for a "last seen" column.
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

// humanRemaining counts a lease down. Leases whose time we never learned show
// a dash; ones that ran out say so rather than counting up.
func humanRemaining(now, expiry time.Time) string {
	if expiry.IsZero() {
		return "-"
	}

	if !expiry.After(now) {
		return "expired"
	}

	return humanDuration(expiry.Sub(now))
}

// addrText renders one address the way an operator writes it: a host route
// as the bare address, a delegated prefix with its length.
func addrText(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}

	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}

	return p.String()
}

// maxShownAddrs bounds the address column. A DHCPv6 reply can carry an IA_NA
// and several prefixes; past a handful the column is noise and the count is
// the useful part.
const maxShownAddrs = 3

// joinAddrs renders a reply's addresses as one comma separated field.
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

// sparkRunes is the eight step block ramp, lowest first.
var sparkRunes = [...]rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// sparkline draws the newest width values as blocks scaled against peak. A
// non-zero value never renders as the empty step, so a single request in a
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

// sparkRune picks the block for one value.
func sparkRune(v, peak uint32) rune {
	steps := uint64(len(sparkRunes) - 1)
	if v == 0 || peak == 0 {
		return sparkRunes[0]
	}

	idx := (uint64(v)*steps + uint64(peak) - 1) / uint64(peak)

	return sparkRunes[min(idx, steps)]
}

// visible picks the rows a pane shows out of every row it could show, and
// reports the index the window starts at so the scroll keys have something to
// move relative to. A following pane is pinned to the newest row.
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

// cell writes a fixed width column built from more than one piece. The
// callback gets its own budget; whatever it leaves is padded out, so a column
// made of a client id plus a dim hostname still lines up with its neighbours.
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
