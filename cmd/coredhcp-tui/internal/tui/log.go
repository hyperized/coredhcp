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

// maxLogLineLen bounds one log line. Lines longer than this are cut: the
// writer keeps the head, which is where the timestamp, level and message are.
const maxLogLineLen = 512

// Widths of the log columns. The prefix is wide enough for the names the
// server logs under, such as "plugins/file".
const (
	logTimeW   = 8
	logLevelW  = 5
	logPrefixW = 14
)

// logEntry is one line as it arrived, with the time we received it. Parsing
// happens when the line is drawn, not when it lands: the ring holds far more
// lines than the pane shows.
type logEntry struct {
	at  time.Time
	raw string
}

// logWriter turns a stream of bytes into whole lines in the model. It is what
// LogWriter hands to the server's slog handler, so it is written to from every
// goroutine that logs and has to hold its own lock.
type logWriter struct {
	mu  sync.Mutex
	buf []byte
	m   *model
	now func() time.Time
}

// Write splits p into lines and stores the complete ones. A partial line is
// held until its newline arrives; a line that never ends is capped rather than
// buffered without limit.
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

// hold appends a fragment to the partial line, ignoring whatever runs past
// the cap.
func (w *logWriter) hold(p []byte) {
	if room := maxLogLineLen - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
}

// Ensure logWriter satisfies the writer contract slog expects.
var _ io.Writer = (*logWriter)(nil)

// logFields is what a slog text-handler line says. parsed is false for a line
// that did not look like key=value pairs, which is drawn as it came in.
type logFields struct {
	at     time.Time
	level  string
	prefix string
	msg    string
	extra  string
	parsed bool
}

// parseLogLine reads a slog text-handler line such as
//
//	time=2026-08-19T12:09:32.986+02:00 level=INFO msg="Listen [::]:547" prefix=server
//
// The scanner is deliberately forgiving: anything that is not a key=value
// pair, or a line with no message at all, is reported as unparsed and shown
// raw instead of being dropped or half rendered.
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

// scanPair reads one key=value pair off the front of s.
func scanPair(s string) (key, value, rest string, ok bool) {
	eq := strings.IndexByte(s, '=')
	space := strings.IndexByte(s, ' ')

	if eq <= 0 || (space >= 0 && space < eq) {
		return "", "", "", false
	}

	value, n := scanValue(s[eq+1:])

	return s[:eq], value, s[eq+1+n:], true
}

// scanValue reads a value, which is either quoted with Go's quoting rules or
// runs to the next space.
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

// parseLogTime reads the handler's timestamp, returning the zero time when it
// is in some other format. The pane then falls back to when the line arrived.
func parseLogTime(v string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}

	return time.Time{}
}

// levelTag colours a log level.
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

// logLines renders the log ring, oldest first.
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

// logLine renders one log line as time, level, prefix and message, with any
// remaining attributes dimmed at the end.
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
