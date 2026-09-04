// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

// errUIFailed stands in for the one error a real UI returns: the screen could
// not be opened.
var errUIFailed = errors.New("screen unavailable")

// fakeUI stands in for tui.UI. run only ever sees the terminal interface, so
// a fake with no screen reaches every path through run, including the ones a
// real terminal makes untestable.
//
// It is written to from the goroutines the server and run start, so every
// field is behind the mutex except the two channels and the two knobs the
// test sets before run is called.
type fakeUI struct {
	// runErr is what Run returns, and block makes Run wait for Stop or for
	// its context instead of returning right away.
	runErr error
	block  bool

	started chan struct{}
	done    chan struct{}

	mu        sync.Mutex
	version   string
	log       bytes.Buffer
	listeners []events.Listener
	plugins   []events.Plugin
	requests  []events.Request
	runs      int
	stops     int
}

func newFakeUI() *fakeUI {
	return &fakeUI{
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (f *fakeUI) Listener(l events.Listener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listeners = append(f.listeners, l)
}

func (f *fakeUI) Plugin(p events.Plugin) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plugins = append(f.plugins, p)
}

func (f *fakeUI) Request(r events.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
}

// Write takes the console log stream, so a test can tell whether run pointed
// the logger at the interface and whether it pointed it back afterwards.
func (f *fakeUI) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.log.Write(p)
}

func (f *fakeUI) LogWriter() io.Writer { return f }

func (f *fakeUI) Run(ctx context.Context) error {
	f.mu.Lock()
	f.runs++
	f.mu.Unlock()
	close(f.started)

	if f.block {
		select {
		case <-f.done:
		case <-ctx.Done():
		}
	}
	return f.runErr
}

func (f *fakeUI) Stop() {
	f.mu.Lock()
	first := f.stops == 0
	f.stops++
	f.mu.Unlock()

	if first {
		close(f.done)
	}
}

func (f *fakeUI) logText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.log.String()
}

func (f *fakeUI) counts() (runs, stops, listeners, pluginEvents int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs, f.stops, len(f.listeners), len(f.plugins)
}

// withFlags sets the package-level pflag values for the duration of the test
// and restores their previous values afterwards. run() reads these directly,
// so tests cannot pass arguments any other way.
func withFlags(t *testing.T, logFile, loglevel, confPath string, pluginsFlag bool) {
	t.Helper()
	origLogFile, origLogLevel := *flagLogFile, *flagLogLevel
	origConfig, origPlugins := *flagConfig, *flagPlugins
	*flagLogFile = logFile
	*flagLogLevel = loglevel
	*flagConfig = confPath
	*flagPlugins = pluginsFlag
	t.Cleanup(func() {
		*flagLogFile = origLogFile
		*flagLogLevel = origLogLevel
		*flagConfig = origConfig
		*flagPlugins = origPlugins
		_ = logger.SetLevel("info")
	})
}

// withUI makes run build f instead of a real terminal interface.
func withUI(t *testing.T, f *fakeUI) {
	t.Helper()
	orig := newUI
	newUI = func(v string) terminal {
		f.mu.Lock()
		f.version = v
		f.mu.Unlock()
		return f
	}
	t.Cleanup(func() { newUI = orig })
}

// withPlugins replaces the compiled-in plugin list for the duration of the
// test. plugins.RegisterPlugin panics on a name that is already registered
// and the registry is a package-level map that lives as long as the test
// binary, so every test that lets run() reach registration brings a plugin
// from testPlugin, which never hands out a name twice.
func withPlugins(t *testing.T, list ...*plugins.Plugin) {
	t.Helper()
	orig := desiredPlugins
	desiredPlugins = list
	t.Cleanup(func() { desiredPlugins = orig })
}

// pluginSeq numbers the plugin names testPlugin hands out. A name is only
// ever registered once in a process, so it cannot be derived from the test's
// name: `go test -count=2` would run the same test twice and register the
// same plugin twice.
var pluginSeq atomic.Uint64

// testPlugin is a plugin that answers nothing and stops nothing, under a name
// no other registration uses. It exists so that a chain can be loaded and
// reported: a plugin without a setup function is skipped while loading, and
// then the server has no plugin to report.
func testPlugin() *plugins.Plugin {
	return &plugins.Plugin{
		Name: "tui-test-plugin-" + strconv.FormatUint(pluginSeq.Add(1), 10),
		Setup4: func(_ ...string) (handler.Handler4, error) {
			return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }, nil
		},
	}
}

// writeConfig writes a DHCPv4 configuration that listens on an ephemeral
// loopback port and runs the named plugin, and returns its path.
//
// The plugins section is mandatory and must be a non-empty list: an empty
// "plugins: []" is indistinguishable from an absent key once it goes through
// spf13/cast, and config.Load rejects both.
func writeConfig(t *testing.T, pluginName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	conf := "server4:\n  listen:\n    - \"127.0.0.1:0\"\n  plugins:\n    - " + pluginName + ": \n"
	require.NoError(t, os.WriteFile(path, []byte(conf), 0o600))
	return path
}

// capturePipe redirects one of the process's standard streams to a pipe and
// returns what was written to it. The returned function may only be called
// once, and the writer must not be handed more than a pipe buffer's worth of
// output before it is.
func capturePipe(t *testing.T, stream **os.File) func() string {
	t.Helper()
	orig := *stream
	r, w, err := os.Pipe()
	require.NoError(t, err)
	*stream = w
	t.Cleanup(func() {
		*stream = orig
		// The pipe is about to be collected, and run() may have left the
		// console pointing at it.
		logger.WithConsole(orig)
	})

	return func() string {
		require.NoError(t, w.Close())
		var buf bytes.Buffer
		_, err := io.Copy(&buf, r)
		require.NoError(t, err)
		return buf.String()
	}
}

// awaitClose waits for ch, failing the test rather than hanging until the go
// test timeout.
func awaitClose(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestRunPluginsFlag covers the -P listing path: it never touches plugin
// registration, config loading, the interface or the server, so it is safe to
// run any number of times in any order relative to the other run() tests.
func TestRunPluginsFlag(t *testing.T) {
	withFlags(t, "", "info", "", true)

	var buf bytes.Buffer
	require.NoError(t, run(&buf))

	out := buf.String()
	for _, p := range desiredPlugins {
		assert.Contains(t, out, p.Name)
	}
	assert.Equal(t, len(desiredPlugins), strings.Count(out, "\n"))
}

// TestRunPluginsFlagWriteError covers the one error the listing can produce.
func TestRunPluginsFlagWriteError(t *testing.T) {
	withFlags(t, "", "info", "", true)

	err := run(failingWriter{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errWriteFailed)
}

var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

func TestRunInvalidLogLevel(t *testing.T) {
	withFlags(t, "", "not-a-real-level", "", false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown log level")
}

func TestRunBadLogFile(t *testing.T) {
	withFlags(t, "/nonexistent-dir-coredhcp-test-xyz/foo.log", "info", "", false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open log file")
}

func TestRunConfigLoadFailure(t *testing.T) {
	badConf := filepath.Join(t.TempDir(), "bad.yml")
	require.NoError(t, os.WriteFile(badConf, []byte("server4:\n  listen: [\n"), 0o600))

	withFlags(t, "", "info", badConf, false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestRunPluginRegistrationFailure drives the registration error branch. A
// nil entry is the only thing RegisterPlugin refuses; every other bad plugin
// makes it panic, which is the registry's problem and not this command's.
func TestRunPluginRegistrationFailure(t *testing.T) {
	withPlugins(t, nil)
	withFlags(t, "", "info", writeConfig(t, "netmask"), false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register plugin")
	assert.Contains(t, err.Error(), "cannot register nil plugin")
}

// TestRunServerStartFailure configures a plugin that was never registered, so
// the chain cannot be loaded and the server never binds anything. The
// interface is built before the server starts, so this also covers taking the
// console stream and handing it back on a path that never draws a frame.
func TestRunServerStartFailure(t *testing.T) {
	f := newFakeUI()
	withUI(t, f)
	withPlugins(t)
	withFlags(t, "", "info", writeConfig(t, "tui-test-unregistered"), false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown plugin")

	runs, stops, listeners, pluginEvents := f.counts()
	assert.Zero(t, runs, "the interface should not be drawn when the server did not start")
	assert.Zero(t, stops)
	assert.Zero(t, listeners)
	assert.Zero(t, pluginEvents)
	assert.Contains(t, f.logText(), "Loading plugins", "the console stream should reach the interface")
}

// TestRunHappyPath runs the whole lifecycle with an interface that quits as
// soon as it is asked to draw, which is what an operator pressing q looks
// like from run's side.
func TestRunHappyPath(t *testing.T) {
	f := newFakeUI()
	withUI(t, f)
	p := testPlugin()
	withPlugins(t, p)
	withFlags(t, "", "info", writeConfig(t, p.Name), false)

	readStderr := capturePipe(t, &os.Stderr)

	require.NoError(t, run(io.Discard))

	runs, stops, listeners, pluginEvents := f.counts()
	assert.Equal(t, 1, runs)
	assert.GreaterOrEqual(t, stops, 1, "closing the listeners should stop the interface")
	assert.Equal(t, 1, listeners, "the bound socket should be reported")
	assert.Equal(t, 1, pluginEvents, "the loaded plugin should be reported")

	f.mu.Lock()
	version := f.version
	f.mu.Unlock()
	assert.NotEmpty(t, version, "the interface should be told which version it is showing")

	assert.Contains(t, f.logText(), "Starting DHCPv4 server")

	// The console goes back to stderr when run returns, so a line logged now
	// lands there and not in the interface's log pane.
	const marker = "console-is-back-on-stderr"
	logger.GetLogger("main").Info(marker)
	assert.Contains(t, readStderr(), marker)
	assert.NotContains(t, f.logText(), marker)
}

// TestRunInterfaceError covers an interface that could not open the screen:
// its error is what the command exits with, and the server is closed on the
// way out all the same.
func TestRunInterfaceError(t *testing.T) {
	f := newFakeUI()
	f.runErr = errUIFailed
	withUI(t, f)
	p := testPlugin()
	withPlugins(t, p)
	withFlags(t, "", "info", writeConfig(t, p.Name), false)

	err := run(io.Discard)
	require.ErrorIs(t, err, errUIFailed)

	_, stops, _, _ := f.counts()
	assert.GreaterOrEqual(t, stops, 1)
}

// TestRunSignalStopsServerAndInterface covers the path where the server ends
// first: SIGTERM closes the listeners, Wait returns, and that is what stops
// an interface which would otherwise draw until the operator quits.
//
// The signal is only sent once Run has been called, because that is the first
// point at which signal.Notify is guaranteed to be armed. Sending it earlier
// would kill the test binary.
func TestRunSignalStopsServerAndInterface(t *testing.T) {
	f := newFakeUI()
	f.block = true
	withUI(t, f)
	p := testPlugin()
	withPlugins(t, p)
	withFlags(t, "", "info", writeConfig(t, p.Name), false)

	errCh := make(chan error, 1)
	go func() { errCh <- run(io.Discard) }()

	awaitClose(t, f.started, "the interface to start drawing")
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case err := <-errCh:
		assert.NoError(t, err, "a shutdown we asked for is not a failure")
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not return after SIGTERM")
	}

	_, stops, listeners, _ := f.counts()
	assert.GreaterOrEqual(t, stops, 1, "the server stopping should stop the interface")
	assert.Equal(t, 1, listeners)
	assert.Contains(t, f.logText(), "shutting down")
}

func TestVersion(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })

	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{name: "no build info", info: nil, ok: false, want: "(devel)"},
		{name: "unversioned build", info: &debug.BuildInfo{}, ok: true, want: "(devel)"},
		{
			name: "module build",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}},
			ok:   true,
			want: "v1.2.3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readBuildInfo = func() (*debug.BuildInfo, bool) { return tc.info, tc.ok }
			assert.Equal(t, tc.want, version())
		})
	}
}

// TestNewUIBuildsRealInterface covers the default newUI. tui.New does not
// touch the terminal, so building one and asking it for its log writer is
// safe in a test.
func TestNewUIBuildsRealInterface(t *testing.T) {
	ui := newUI("v1.2.3")
	require.NotNil(t, ui)
	assert.NotNil(t, ui.LogWriter())
}

// TestMainListsPlugins covers main(). os.Args is replaced because pflag
// parses it and the test binary's own -test.* flags would fail the parse and
// exit the process. The plugin listing is the only flow main() can finish
// in-process; the error path is TestMainExitsNonZeroOnFailure below.
func TestMainListsPlugins(t *testing.T) {
	origArgs := os.Args
	os.Args = []string{"coredhcp-tui"}
	t.Cleanup(func() { os.Args = origArgs })

	withFlags(t, "", "info", "", true)
	readStdout := capturePipe(t, &os.Stdout)

	main()

	out := readStdout()
	for _, p := range desiredPlugins {
		assert.Contains(t, out, p.Name)
	}
}

// TestMainExitsNonZeroOnFailure runs main() in a second copy of this test
// binary, because the failure path ends in logger.Fatal and that calls
// os.Exit. The child inherits GOCOVERDIR under `go test -cover`, so the
// statement is counted as covered even though it runs in another process.
//
// What it proves is the part that matters to whoever runs the binary: a run()
// that fails leaves a non-zero exit status behind.
func TestMainExitsNonZeroOnFailure(t *testing.T) {
	if os.Getenv("COREDHCP_TUI_TEST_MAIN_FATAL") == "1" {
		os.Args = []string{"coredhcp-tui", "--loglevel", "not-a-real-level"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainExitsNonZeroOnFailure$")
	cmd.Env = append(os.Environ(), "COREDHCP_TUI_TEST_MAIN_FATAL=1")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "main() should have exited non-zero, output: %s", out)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, string(out), "unknown log level")
}
