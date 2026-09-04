// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package logger provides the shared logging facilities used by the server
// and its plugins, backed by the standard library's log/slog.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// levelFatal sits above slog.LevelError so fatal messages survive every
// verbosity setting except "none".
const levelFatal = slog.LevelError + 4

// levels maps the accepted level names to slog levels. "none" sits above
// fatal, so nothing is ever printed.
var levels = map[string]slog.Level{
	"none":    levelFatal + 4,
	"debug":   slog.LevelDebug,
	"info":    slog.LevelInfo,
	"warning": slog.LevelWarn,
	"error":   slog.LevelError,
	"fatal":   levelFatal,
}

var (
	level    slog.LevelVar // defaults to Info
	out      = switchableWriter{console: os.Stderr}
	base     *slog.Logger
	baseOnce sync.Once
)

// switchableWriter fans log lines out to the console and an optional file,
// both swappable at runtime.
type switchableWriter struct {
	mu      sync.Mutex
	console io.Writer
	file    io.Writer
}

func (w *switchableWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.console != nil {
		if n, err := w.console.Write(p); err != nil {
			return n, err
		}
	}
	if w.file != nil {
		if n, err := w.file.Write(p); err != nil {
			return n, err
		}
	}
	return len(p), nil
}

// replaceAttr renders the custom fatal level with its proper name instead of
// slog's "ERROR+4".
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if lvl, ok := a.Value.Any().(slog.Level); ok && lvl >= levelFatal {
			a.Value = slog.StringValue("FATAL")
		}
	}
	return a
}

// Logger is a leveled, printf-style front end over log/slog, keeping the
// call shapes the code base has always used.
type Logger struct {
	s *slog.Logger
}

// GetLogger returns a logger that tags every line with the given prefix.
func GetLogger(prefix string) *Logger {
	baseOnce.Do(func() {
		base = slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{
			Level:       &level,
			ReplaceAttr: replaceAttr,
		}))
	})
	if prefix == "" {
		prefix = "<no prefix>"
	}
	return &Logger{s: base.With("prefix", prefix)}
}

// With returns a logger with additional structured context attached as
// alternating key/value pairs.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{s: l.s.With(args...)}
}

func (l *Logger) log(lvl slog.Level, msg string) {
	l.s.Log(context.Background(), lvl, msg)
}

// Debug logs at debug level.
func (l *Logger) Debug(args ...any) { l.log(slog.LevelDebug, fmt.Sprint(args...)) }

// Debugf logs a formatted message at debug level.
func (l *Logger) Debugf(format string, args ...any) {
	l.log(slog.LevelDebug, fmt.Sprintf(format, args...))
}

// Info logs at info level.
func (l *Logger) Info(args ...any) { l.log(slog.LevelInfo, fmt.Sprint(args...)) }

// Infof logs a formatted message at info level.
func (l *Logger) Infof(format string, args ...any) {
	l.log(slog.LevelInfo, fmt.Sprintf(format, args...))
}

// Print logs at info level.
func (l *Logger) Print(args ...any) { l.Info(args...) }

// Printf logs a formatted message at info level.
func (l *Logger) Printf(format string, args ...any) { l.Infof(format, args...) }

// Println logs at info level.
func (l *Logger) Println(args ...any) { l.Info(args...) }

// Warning logs at warning level.
func (l *Logger) Warning(args ...any) { l.log(slog.LevelWarn, fmt.Sprint(args...)) }

// Warningf logs a formatted message at warning level.
func (l *Logger) Warningf(format string, args ...any) {
	l.log(slog.LevelWarn, fmt.Sprintf(format, args...))
}

// Warningln logs at warning level.
func (l *Logger) Warningln(args ...any) { l.Warning(args...) }

// Error logs at error level.
func (l *Logger) Error(args ...any) { l.log(slog.LevelError, fmt.Sprint(args...)) }

// Errorf logs a formatted message at error level.
func (l *Logger) Errorf(format string, args ...any) {
	l.log(slog.LevelError, fmt.Sprintf(format, args...))
}

// Fatal logs at fatal level and exits with status 1.
func (l *Logger) Fatal(args ...any) {
	l.log(levelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf logs a formatted message at fatal level and exits with status 1.
func (l *Logger) Fatalf(format string, args ...any) {
	l.log(levelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Panicf logs a formatted message at error level and panics with it.
func (l *Logger) Panicf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.log(slog.LevelError, msg)
	panic(msg)
}

// SetLevel sets the verbosity for all loggers. Accepted names come from
// Levels.
func SetLevel(name string) error {
	lvl, ok := levels[strings.ToLower(name)]
	if !ok {
		return fmt.Errorf("unknown log level '%s', valid levels are %v", name, Levels())
	}
	level.Set(lvl)
	return nil
}

// Levels lists the accepted log level names.
func Levels() []string {
	names := make([]string, 0, len(levels))
	for name := range levels {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// WithFile appends every log line to the given file in addition to the
// existing output. Calling it again replaces the previous file.
func WithFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	if prev, ok := out.file.(*os.File); ok {
		_ = prev.Close()
	}
	out.file = f
	return nil
}

// WithNoStdOutErr disables logging to stderr.
func WithNoStdOutErr() {
	WithConsole(nil)
}

// WithConsole replaces the console stream, the same one WithNoStdOutErr
// disables. A nil w disables console output. The file writer set by
// WithFile is unaffected and keeps receiving lines. Safe to call while the
// server is logging.
func WithConsole(w io.Writer) {
	out.mu.Lock()
	defer out.mu.Unlock()
	out.console = w
}
