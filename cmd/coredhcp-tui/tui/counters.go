// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"sort"
	"strconv"

	"github.com/coredhcp/coredhcp/events"
)

// Four: a busy family uses three or four message types and the tail is noise.
const maxCounterTypes = 4

var pathLabels = [pathCount]string{"none", "unicast", "bcast", "l2"}

func counterLines(s snapshot, width int) []string {
	lines := make([]string, 0, 8)

	for _, f := range renderFamilies {
		c, ok := s.counts[f]
		if !ok {
			lines = append(lines, counterHeader(f, 0, width), newDim(width, "  no requests"))

			continue
		}

		lines = append(lines,
			counterHeader(f, c.total, width),
			typeLine("in ", c.in, width),
			typeLine("out", c.out, width),
			problemLine(c, width),
			pathLine(c, width),
		)
	}

	return lines
}

func counterHeader(f events.Family, total uint64, width int) string {
	l := newLine(width)
	l.text(tagBold, f.String())
	l.space(1)
	l.text(tagDim, humanCount(total)+" req")

	return l.String()
}

func typeLine(label string, counts map[string]uint64, width int) string {
	l := newLine(width)
	l.space(1)
	l.col(tagDim, label, 3)

	for _, kv := range topTypes(counts, maxCounterTypes) {
		l.space(1)
		l.text(tagPlain, kv.name)
		l.text(tagDim, " "+humanCount(kv.count))
	}

	return l.String()
}

type namedCount struct {
	name  string
	count uint64
}

// Ties break on name so two runs with the same traffic render identically.
func topTypes(counts map[string]uint64, n int) []namedCount {
	out := make([]namedCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, namedCount{name: name, count: count})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}

		return out[i].name < out[j].name
	})

	return out[:min(len(out), n)]
}

// Coloured only when the count is non-zero, so a healthy server is not a wall
// of red zeroes.
func problemLine(c familyCounters, width int) string {
	l := newLine(width)
	l.space(1)

	for i, p := range []struct {
		label string
		count uint64
		tag   string
	}{
		{"drop", c.dropped, tagWarn},
		{"parse", c.parseErrs, tagBad},
		{"unsup", c.unsupported, tagBad},
		{"send", c.sendErrs, tagBad},
	} {
		if i > 0 {
			l.space(1)
		}

		tag := tagDim
		if p.count > 0 {
			tag = p.tag
		}

		l.text(tagDim, p.label+" ")
		l.text(tag, strconv.FormatUint(p.count, 10))
	}

	return l.String()
}

func pathLine(c familyCounters, width int) string {
	l := newLine(width)
	l.space(1)
	l.text(tagDim, "path")

	empty := true

	for i, count := range c.paths {
		if count == 0 || events.ReplyPath(i) == events.PathNone {
			continue
		}

		empty = false

		l.space(1)
		l.text(tagPlain, pathLabels[i])
		l.text(tagDim, " "+humanCount(count))
	}

	if empty {
		l.space(1)
		l.text(tagDim, "-")
	}

	return l.String()
}
