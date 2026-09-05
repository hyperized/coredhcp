// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/coredhcp/coredhcp/events"
)

const rateLabelW = 4

// Each sparkline is scaled against its own peak, so the label has to carry the
// magnitude the shape cannot.
func rateLines(s snapshot, width int) []string {
	reqPeak := peak(s.reqRate)
	errTotal := sum(s.errRate)

	return []string{
		sparkRow("req", s.reqRate, reqPeak, "max "+strconv.FormatUint(uint64(reqPeak), 10)+"/s", width),
		sparkRow("err", s.errRate, peak(s.errRate), errLabel(errTotal), width),
		chainLatencyLine(s.traffic, width),
	}
}

// The error peak is usually one, and a sparkline of ones says nothing.
func errLabel(total uint64) string {
	if total == 0 {
		return "none in 60 s"
	}

	return humanCount(total) + " in 60 s"
}

func sparkRow(label string, values []uint32, top uint32, tail string, width int) string {
	l := newLine(width)
	l.col(tagDim, label, rateLabelW)

	tailW := utf8.RuneCountInString(tail)
	graph := max(l.room()-tailW-2, 0)

	tag := tagPlain
	if label == "err" && top > 0 {
		tag = tagBad
	}

	l.text(tag, sparkline(values, top, graph))
	l.space(max(l.room()-tailW, 0))
	l.text(tagDim, tail)

	return l.String()
}

func chainLatencyLine(traffic []events.Request, width int) string {
	l := newLine(width)
	l.col(tagDim, "chain", rateLabelW+2)

	median, top, ok := chainLatency(traffic)
	if !ok {
		l.text(tagDim, "no timings yet")

		return l.String()
	}

	l.text(tagDim, "p50 ")
	l.text(tagPlain, humanDuration(median))
	l.text(tagDim, "  max ")
	l.text(latencyTag(top), humanDuration(top))

	return l.String()
}

// A DHCP client waits seconds, so this is not a deadline: it is where a plugin
// is doing blocking work worth looking at.
const slowChain = 250 * time.Millisecond

func latencyTag(d time.Duration) string {
	if d >= slowChain {
		return tagWarn
	}

	return tagPlain
}

func chainLatency(traffic []events.Request) (median, top time.Duration, ok bool) {
	durations := make([]time.Duration, 0, len(traffic))

	for i := range traffic {
		if traffic[i].Duration > 0 {
			durations = append(durations, traffic[i].Duration)
		}
	}

	if len(durations) == 0 {
		return 0, 0, false
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	return durations[len(durations)/2], durations[len(durations)-1], true
}
