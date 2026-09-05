// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A longer line is cut at the head, which is where the timestamp, level and
// message are.
const maxLogLineLen = 512

// The prefix column fits the names the server logs under, such as "plugins/file".
const (
	logTimeW   = 8
	logLevelW  = 5
	logPrefixW = 14
)

// Held raw: parsing happens at draw time, and the ring keeps far more lines
// than the pane ever shows.
type logEntry struct {
	at  time.Time
	raw string
}

// Written to from every goroutine that logs, so it carries its own lock.
type logWriter struct {
	mu  sync.Mutex
	buf []byte
	m   *model
	now func() time.Time
}

// Write holds a partial line until its newline arrives, capping one that never
// ends rather than buffering it without limit.
func (w *logWriter) Write(p []byte) (int, error) {
	total := len(p)

	w.mu.Lock()
	defer w.mu.Unlock()

	for {
		nl := bytes.IndexByte(p, '\n')
		if nl < 0 {
			w.hold(p)

			break
		}

		w.hold(p[:nl])
		w.m.addLog(w.now(), string(bytes.TrimSuffix(w.buf, []byte("\r"))))
		w.buf = w.buf[:0]

		p = p[nl+1:]
	}

	return total, nil
}

func (w *logWriter) hold(p []byte) {
	if room := maxLogLineLen - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
}

var _ io.Writer = (*logWriter)(nil)

// parsed is false for a line that was not key=value shaped; it is drawn raw.
type logFields struct {
	at     time.Time
	level  string
	prefix string
	msg    string
	extra  string
	parsed bool
}

// Deliberately forgiving: anything not key=value shaped is reported unparsed
// and shown raw rather than dropped or half rendered.
func parseLogLine(raw string) logFields {
	var (
		f     logFields
		extra []string
		rest  = raw
	)

	for {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			break
		}

		key, value, remainder, ok := scanPair(rest)
		if !ok {
			return logFields{}
		}

		rest = remainder

		switch key {
		case "time":
			f.at = parseLogTime(value)
		case "level":
			f.level = value
		case "prefix":
			f.prefix = value
		case "msg":
			f.msg, f.parsed = value, true
		default:
			extra = append(extra, key+"="+value)
		}
	}

	f.extra = strings.Join(extra, " ")

	return f
}

func scanPair(s string) (key, value, rest string, ok bool) {
	eq := strings.IndexByte(s, '=')
	space := strings.IndexByte(s, ' ')

	if eq <= 0 || (space >= 0 && space < eq) {
		return "", "", "", false
	}

	value, n := scanValue(s[eq+1:])

	return s[:eq], value, s[eq+1+n:], true
}

func scanValue(s string) (string, int) {
	if s == "" || s[0] != '"' {
		if i := strings.IndexByte(s, ' '); i >= 0 {
			return s[:i], i
		}

		return s, len(s)
	}

	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			if v, err := strconv.Unquote(s[:i+1]); err == nil {
				return v, i + 1
			}

			return s[:i+1], i + 1
		}
	}

	return s, len(s)
}

// A zero return means the pane falls back to when the line arrived.
func parseLogTime(v string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}

	return time.Time{}
}

func levelTag(level string) string {
	switch strings.ToUpper(level) {
	case "INFO":
		return tagGood
	case "WARN", "WARNING":
		return tagWarn
	case "ERROR", "FATAL", "PANIC":
		return tagBad
	case "DEBUG", "TRACE":
		return tagDim
	}

	return tagPlain
}

func logLines(s snapshot, width int) []string {
	if len(s.logs) == 0 {
		return []string{newDim(width, "no log lines yet")}
	}

	lines := make([]string, 0, len(s.logs))
	for _, e := range s.logs {
		lines = append(lines, logLine(e, width))
	}

	return lines
}

func logLine(e logEntry, width int) string {
	l := newLine(width)

	f := parseLogLine(e.raw)
	if !f.parsed {
		l.text(tagDim, e.raw)

		return l.String()
	}

	at := f.at
	if at.IsZero() {
		at = e.at
	}

	l.col(tagDim, at.Format("15:04:05"), logTimeW)
	l.space(1)
	l.col(levelTag(f.level), strings.ToUpper(f.level), logLevelW)
	l.space(1)
	l.col(tagDim, f.prefix, logPrefixW)
	l.space(1)
	l.text(tagPlain, f.msg)

	if f.extra != "" {
		l.space(1)
		l.text(tagDim, f.extra)
	}

	return l.String()
}
