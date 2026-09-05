// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

// withFlags sets the package-level pflag values for the duration of the
// test and restores their previous values afterwards. run() reads these
// directly, so tests cannot pass arguments any other way.
func withFlags(t *testing.T, logFile, loglevel, confPath string, noStdout, pluginsFlag bool) {
	t.Helper()
	origLogFile, origLogNoStdout := *flagLogFile, *flagLogNoStdout
	origLogLevel, origConfig, origPlugins := *flagLogLevel, *flagConfig, *flagPlugins
	*flagLogFile = logFile
	*flagLogNoStdout = noStdout
	*flagLogLevel = loglevel
	*flagConfig = confPath
	*flagPlugins = pluginsFlag
	t.Cleanup(func() {
		*flagLogFile = origLogFile
		*flagLogNoStdout = origLogNoStdout
		*flagLogLevel = origLogLevel
		*flagConfig = origConfig
		*flagPlugins = origPlugins
		_ = logger.SetLevel("info")
	})
}

// TestRunPluginsFlag covers the -P listing path: it never touches plugin
// registration, config loading, or the server, so it is safe to run any
// number of times in any order relative to the other run() tests.
func TestRunPluginsFlag(t *testing.T) {
	withFlags(t, "", "info", "", false, true)
	var buf bytes.Buffer
	err := run(&buf)
	require.NoError(t, err)

	out := buf.String()
	for _, p := range desiredPlugins {
		assert.Contains(t, out, p.Name)
	}
	assert.Equal(t, len(desiredPlugins), strings.Count(out, "\n"))
}

func TestRunInvalidLogLevel(t *testing.T) {
	withFlags(t, "", "not-a-real-level", "", false, false)
	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown log level")
}

func TestRunBadLogFile(t *testing.T) {
	withFlags(t, "/nonexistent-dir-coredhcp-test-xyz/foo.log", "info", "", false, false)
	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open log file")
}

func TestRunConfigLoadFailure(t *testing.T) {
	dir := t.TempDir()
	badConf := filepath.Join(dir, "bad.yml")
	require.NoError(t, os.WriteFile(badConf, []byte("server4:\n  listen: [\n"), 0o600))

	withFlags(t, "", "info", badConf, false, false)
	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// unregisterPlugins hands the package-global plugin registry back the way it
// was found. run() registers desiredPlugins unconditionally on every call
// that gets past config loading, and plugins.RegisterPlugin panics on a
// duplicate name, so every test that lets run() get that far has to clean up
// after itself or the next one dies on the panic.
func unregisterPlugins(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, p := range desiredPlugins {
			delete(plugins.RegisteredPlugins, p.Name)
		}
	})
}

// TestRunFullHappyPath is the exit-status contract for a clean shutdown: a
// listener closed on purpose is not a failure, so SIGTERM has to leave run()
// returning nil and the process exiting 0. Since run() now hands the error
// from srv.Wait() straight to main, a regression here would turn every
// ordinary `systemctl stop` into a failed unit.
//
// There is no hook to observe "the server is now listening and signal
// handling is armed" from outside run(), so the delay before sending
// SIGTERM is a real sleep rather than a channel sync.
func TestRunFullHappyPath(t *testing.T) {
	unregisterPlugins(t)
	dir := t.TempDir()
	confPath := filepath.Join(dir, "config.yml")
	// The plugins section is mandatory and must be a non-empty list: an
	// empty "plugins: []" is indistinguishable from an absent key once it
	// goes through spf13/cast, and config.Load rejects both.
	conf := "server4:\n  listen:\n    - \"127.0.0.1:0\"\n  plugins:\n    - netmask: 255.255.255.0\n"
	require.NoError(t, os.WriteFile(confPath, []byte(conf), 0o600))

	withFlags(t, "", "none", confPath, true, false)

	errCh := make(chan error, 1)
	go func() { errCh <- run(io.Discard) }()

	time.Sleep(500 * time.Millisecond)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after SIGTERM")
	}
}

// A configuration that binds nothing, which `listen: []` produces, has to
// come back as an error so main exits non-zero. It used to bind no socket,
// report success, and then panic inside Wait.
func TestRunEmptyListenFails(t *testing.T) {
	unregisterPlugins(t)
	dir := t.TempDir()
	confPath := filepath.Join(dir, "config.yml")
	conf := "server4:\n  listen: []\n  plugins:\n    - netmask: 255.255.255.0\n"
	require.NoError(t, os.WriteFile(confPath, []byte(conf), 0o600))

	withFlags(t, "", "none", confPath, true, false)

	err := run(io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no listen addresses configured")
}
