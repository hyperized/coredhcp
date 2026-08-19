// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package logger

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests reach into the package's unexported singletons (level, out,
// base), so they must run sequentially: none of them call t.Parallel.

// captureConsole swaps out.console for a buffer for the duration of the
// test and restores the previous writer afterwards.
func captureConsole(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	out.mu.Lock()
	prev := out.console
	out.console = buf
	out.mu.Unlock()
	t.Cleanup(func() {
		out.mu.Lock()
		out.console = prev
		out.mu.Unlock()
	})
	return buf
}

// resetLevel restores the level in effect before the test once it finishes.
func resetLevel(t *testing.T) {
	t.Helper()
	prev := level.Level()
	t.Cleanup(func() { level.Set(prev) })
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestSwitchableWriterWrite(t *testing.T) {
	t.Run("both writers succeed", func(t *testing.T) {
		var c, f bytes.Buffer
		w := switchableWriter{console: &c, file: &f}
		n, err := w.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "hello", c.String())
		assert.Equal(t, "hello", f.String())
	})

	t.Run("nil console and file are skipped", func(t *testing.T) {
		w := switchableWriter{}
		n, err := w.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
	})

	t.Run("console error short-circuits before file", func(t *testing.T) {
		var f bytes.Buffer
		boom := errors.New("console boom")
		w := switchableWriter{console: failWriter{err: boom}, file: &f}
		n, err := w.Write([]byte("hello"))
		assert.ErrorIs(t, err, boom)
		assert.Equal(t, 0, n)
		assert.Empty(t, f.String())
	})

	t.Run("file error propagates after console succeeds", func(t *testing.T) {
		var c bytes.Buffer
		boom := errors.New("file boom")
		w := switchableWriter{console: &c, file: failWriter{err: boom}}
		n, err := w.Write([]byte("hello"))
		assert.ErrorIs(t, err, boom)
		assert.Equal(t, 0, n)
		assert.Equal(t, "hello", c.String())
	})
}

func TestReplaceAttr(t *testing.T) {
	cases := []struct {
		name string
		in   slog.Attr
		want slog.Attr
	}{
		{
			name: "fatal level renamed",
			in:   slog.Any(slog.LevelKey, levelFatal),
			want: slog.String(slog.LevelKey, "FATAL"),
		},
		{
			name: "level above fatal also renamed",
			in:   slog.Any(slog.LevelKey, levelFatal+4),
			want: slog.String(slog.LevelKey, "FATAL"),
		},
		{
			name: "ordinary level left untouched",
			in:   slog.Any(slog.LevelKey, slog.LevelInfo),
			want: slog.Any(slog.LevelKey, slog.LevelInfo),
		},
		{
			name: "non-level value left untouched",
			in:   slog.String(slog.LevelKey, "not-a-level"),
			want: slog.String(slog.LevelKey, "not-a-level"),
		},
		{
			name: "non-level key left untouched",
			in:   slog.String("msg", "hello"),
			want: slog.String("msg", "hello"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replaceAttr(nil, tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLevelsSortedInternal(t *testing.T) {
	got := Levels()
	want := []string{"debug", "error", "fatal", "info", "none", "warning"}
	assert.Equal(t, want, got)
}

func TestSetLevelInvalid(t *testing.T) {
	resetLevel(t)
	err := SetLevel("bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
	for _, name := range Levels() {
		assert.Contains(t, err.Error(), name)
	}
}

func TestGetLoggerPrefix(t *testing.T) {
	resetLevel(t)
	require.NoError(t, SetLevel("info"))

	cases := []struct {
		name       string
		prefix     string
		wantSubstr string
	}{
		{name: "empty prefix falls back", prefix: "", wantSubstr: `prefix="<no prefix>"`},
		{name: "custom prefix kept", prefix: "myplugin", wantSubstr: "prefix=myplugin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureConsole(t)
			l := GetLogger(tc.prefix)
			l.Info("hi")
			assert.Contains(t, buf.String(), tc.wantSubstr)
		})
	}
}

func TestWith(t *testing.T) {
	resetLevel(t)
	require.NoError(t, SetLevel("info"))
	buf := captureConsole(t)

	l := GetLogger("withtest")
	l.Info("baseline")
	assert.NotContains(t, buf.String(), "extra=attr")

	buf.Reset()
	l2 := l.With("extra", "attr")
	l2.Info("withattr")
	assert.Contains(t, buf.String(), "extra=attr")
}

func TestLoggerMethods(t *testing.T) {
	resetLevel(t)
	require.NoError(t, SetLevel("debug"))

	cases := []struct {
		name      string
		call      func(l *Logger)
		wantLevel string
		wantMsg   string
	}{
		{"Debug", func(l *Logger) { l.Debug("deb", "ug") }, "DEBUG", "debug"},
		{"Debugf", func(l *Logger) { l.Debugf("deb%s", "ug") }, "DEBUG", "debug"},
		{"Info", func(l *Logger) { l.Info("inf", "o") }, "INFO", "info"},
		{"Infof", func(l *Logger) { l.Infof("inf%s", "o") }, "INFO", "info"},
		{"Print", func(l *Logger) { l.Print("pri", "nt") }, "INFO", "print"},
		{"Printf", func(l *Logger) { l.Printf("pri%s", "nt") }, "INFO", "print"},
		{"Println", func(l *Logger) { l.Println("prin", "tln") }, "INFO", "println"},
		{"Warning", func(l *Logger) { l.Warning("war", "ning") }, "WARN", "warning"},
		{"Warningf", func(l *Logger) { l.Warningf("war%s", "ning") }, "WARN", "warning"},
		{"Warningln", func(l *Logger) { l.Warningln("warnin", "gln") }, "WARN", "warningln"},
		{"Error", func(l *Logger) { l.Error("err", "or") }, "ERROR", "error"},
		{"Errorf", func(l *Logger) { l.Errorf("err%s", "or") }, "ERROR", "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureConsole(t)
			l := GetLogger("methodtest")
			tc.call(l)
			got := buf.String()
			assert.Contains(t, got, "level="+tc.wantLevel)
			assert.Contains(t, got, tc.wantMsg)
		})
	}
}

func TestLevelFiltering(t *testing.T) {
	resetLevel(t)

	cases := []struct {
		setLevel                         string
		debug, info, warn, errLvl, fatal bool
	}{
		{"debug", true, true, true, true, true},
		{"info", false, true, true, true, true},
		{"warning", false, false, true, true, true},
		{"error", false, false, false, true, true},
		{"fatal", false, false, false, false, true},
		{"none", false, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.setLevel, func(t *testing.T) {
			require.NoError(t, SetLevel(tc.setLevel))
			buf := captureConsole(t)
			l := GetLogger("filtertest")

			buf.Reset()
			l.Debug("MARK_DEBUG")
			assert.Equal(t, tc.debug, bytes.Contains(buf.Bytes(), []byte("MARK_DEBUG")))

			buf.Reset()
			l.Info("MARK_INFO")
			assert.Equal(t, tc.info, bytes.Contains(buf.Bytes(), []byte("MARK_INFO")))

			buf.Reset()
			l.Warning("MARK_WARN")
			assert.Equal(t, tc.warn, bytes.Contains(buf.Bytes(), []byte("MARK_WARN")))

			buf.Reset()
			l.Error("MARK_ERROR")
			assert.Equal(t, tc.errLvl, bytes.Contains(buf.Bytes(), []byte("MARK_ERROR")))

			buf.Reset()
			l.log(levelFatal, "MARK_FATAL")
			assert.Equal(t, tc.fatal, bytes.Contains(buf.Bytes(), []byte("MARK_FATAL")))
		})
	}
}

func TestPanicf(t *testing.T) {
	resetLevel(t)
	require.NoError(t, SetLevel("info"))
	buf := captureConsole(t)

	l := GetLogger("panictest")
	assert.PanicsWithValue(t, "boom 42", func() {
		l.Panicf("boom %d", 42)
	})
	assert.Contains(t, buf.String(), "level=ERROR")
	assert.Contains(t, buf.String(), "boom 42")
}

func TestWithFile(t *testing.T) {
	resetLevel(t)
	require.NoError(t, SetLevel("info"))
	captureConsole(t) // keep stderr quiet during the test
	t.Cleanup(func() {
		out.mu.Lock()
		if f, ok := out.file.(*os.File); ok {
			_ = f.Close()
		}
		out.file = nil
		out.mu.Unlock()
	})

	dir := t.TempDir()
	path1 := filepath.Join(dir, "first.log")
	require.NoError(t, WithFile(path1))

	l := GetLogger("filetest")
	l.Info("to-first-file")

	content1, err := os.ReadFile(path1)
	require.NoError(t, err)
	assert.Contains(t, string(content1), "to-first-file")

	// A second call must replace the first file, closing it.
	path2 := filepath.Join(dir, "second.log")
	require.NoError(t, WithFile(path2))

	l.Info("to-second-file")

	content2, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.Contains(t, string(content2), "to-second-file")

	content1After, err := os.ReadFile(path1)
	require.NoError(t, err)
	assert.NotContains(t, string(content1After), "to-second-file")
}

func TestWithFileOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "x.log")
	err := WithFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open log file")
}

func TestWithNoStdOutErr(t *testing.T) {
	out.mu.Lock()
	prev := out.console
	out.mu.Unlock()
	t.Cleanup(func() {
		out.mu.Lock()
		out.console = prev
		out.mu.Unlock()
	})

	WithNoStdOutErr()

	out.mu.Lock()
	got := out.console
	out.mu.Unlock()
	assert.Nil(t, got)
}

// TestFatalExits and TestFatalfExits cover Fatal/Fatalf's os.Exit(1) call by
// re-executing this test binary in a child process: the guard env vars pick
// the child out of the normal test run, and the parent inspects the child's
// exit code and stderr.

func TestFatalExits(t *testing.T) {
	if os.Getenv("COREDHCP_LOGGER_TEST_FATAL_CHILD") == "1" {
		l := GetLogger("fataltest")
		l.Fatal("boom-fatal")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalExits$")
	cmd.Env = append(os.Environ(), "COREDHCP_LOGGER_TEST_FATAL_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "expected an *exec.ExitError, got %v", err)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stderr.String(), "level=FATAL")
	assert.Contains(t, stderr.String(), "boom-fatal")
}

func TestFatalfExits(t *testing.T) {
	if os.Getenv("COREDHCP_LOGGER_TEST_FATALF_CHILD") == "1" {
		l := GetLogger("fatalftest")
		l.Fatalf("boom-fatalf %d", 42)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalfExits$")
	cmd.Env = append(os.Environ(), "COREDHCP_LOGGER_TEST_FATALF_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "expected an *exec.ExitError, got %v", err)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stderr.String(), "level=FATAL")
	assert.Contains(t, stderr.String(), "boom-fatalf 42")
}
