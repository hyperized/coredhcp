// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/coredhcp/coredhcp/events"
)

// A long run of nothing but hex is a token or a key, never a name or address.
var hexSecret = regexp.MustCompile(`^[A-Fa-f0-9]{32,}$`)

// Long arguments are usually paths, and a path's tail does not identify the plugin.
const maxArgsW = 40

// The events package warns that plugin arguments may hold secrets, and this
// pane is the one place they would otherwise reach a shared screen.
func redactArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}

	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, redactArg(a))
	}

	return strings.Join(out, " ")
}

// An "env:" reference names a variable rather than holding its value, so it stays.
func redactArg(a string) string {
	if strings.HasPrefix(a, "env:") {
		return a
	}

	if hexSecret.MatchString(a) {
		return "***"
	}

	return redactUserinfo(a)
}

// The user name survives: which account a plugin connects as is worth seeing.
func redactUserinfo(a string) string {
	scheme := strings.Index(a, "://")
	if scheme < 0 {
		return a
	}

	rest := a[scheme+3:]

	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return a
	}

	userinfo := rest[:at]
	if strings.ContainsAny(userinfo, "/?#") {
		return a
	}

	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		return a
	}

	return a[:scheme+3] + userinfo[:colon] + ":***@" + rest[at+1:]
}

// Kept as data so a column's width can be measured before it is written.
type tagged struct {
	tag  string
	text string
}

func taggedWidth(parts []tagged) int {
	width := 0
	for _, p := range parts {
		width += utf8.RuneCountInString(p.text)
	}

	return width
}

func chainCounts(l chainLink) []tagged {
	parts := []tagged{{tagDim, "×" + strconv.FormatUint(l.reached, 10)}}

	if l.replied > 0 {
		parts = append(parts, tagged{tagPlain, " "}, tagged{tagGood, "✓" + strconv.FormatUint(l.replied, 10)})
	}

	if l.dropped > 0 {
		parts = append(parts, tagged{tagPlain, " "}, tagged{tagBad, "✗" + strconv.FormatUint(l.dropped, 10)})
	}

	return parts
}

func pluginLines(s snapshot, width int) []string {
	lines := make([]string, 0, 8)

	for _, f := range renderFamilies {
		lines = append(lines, familyHeader(s, f, width))

		links := s.chains[f]
		if len(links) == 0 {
			lines = append(lines, newDim(width, "  not configured"))

			continue
		}

		for i, l := range links {
			lines = append(lines, chainLine(i+1, l, width))
		}
	}

	return lines
}

func familyHeader(s snapshot, f events.Family, width int) string {
	l := newLine(width)
	l.text(tagBold, f.String())

	addrs := listenerText(s.listeners, f)
	if addrs == "" {
		l.space(1)
		l.text(tagDim, "no listener")

		return l.String()
	}

	l.space(1)
	l.text(tagPlain, addrs)

	return l.String()
}

func listenerText(listeners []events.Listener, f events.Family) string {
	parts := make([]string, 0, len(listeners))

	for _, l := range listeners {
		if l.Family != f {
			continue
		}

		text := l.Address
		if l.Interface != "" {
			text += " (" + l.Interface + ")"
		}

		parts = append(parts, text)
	}

	return strings.Join(parts, ", ")
}

func chainLine(pos int, link chainLink, width int) string {
	counts := chainCounts(link)
	countsW := taggedWidth(counts)

	l := newLine(width)

	l.cell(max(width-countsW-1, 0), func(b *lineBuf) {
		b.colRight(tagDim, strconv.Itoa(pos), 2)
		b.space(1)
		b.text(tagPlain, link.name)

		if args := redactArgs(link.args); args != "" && b.room() > 1 {
			b.space(1)
			b.text(tagDim, clipTo(args, maxArgsW))
		}
	})

	l.space(1)

	for _, p := range counts {
		l.text(p.tag, p.text)
	}

	return l.String()
}

func clipTo(s string, n int) string {
	out, _ := clip(s, n)

	return out
}
