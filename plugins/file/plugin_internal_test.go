// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
)

// These two cases substitute the fsnotifyNewWatcher/watcherAdd seams to
// simulate autorefresh setup failures. Real filesystem operations can't
// deterministically fail fsnotify.NewWatcher (an fd exhaustion condition) or
// Watcher.Add on a file that was just successfully read, so the production
// code exposes these as indirections purely for this test.

func TestSetupFileWatcherCreateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.txt")
	require.NoError(t, os.WriteFile(path, []byte("aa:bb:cc:dd:ee:ff 192.0.2.1\n"), 0o600))

	orig := fsnotifyNewWatcher
	t.Cleanup(func() { fsnotifyNewWatcher = orig })
	fsnotifyNewWatcher = func() (*fsnotify.Watcher, error) {
		return nil, errors.New("simulated watcher creation failure")
	}

	_, _, err := setupFile(false, path, autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create watcher")
}

func TestSetupFileWatcherAddError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.txt")
	require.NoError(t, os.WriteFile(path, []byte("aa:bb:cc:dd:ee:ff 192.0.2.1\n"), 0o600))

	orig := watcherAdd
	t.Cleanup(func() { watcherAdd = orig })
	watcherAdd = func(*fsnotify.Watcher, string) error {
		return errors.New("simulated watch failure")
	}

	_, _, err := setupFile(false, path, autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to watch")
}

// newWatchLoopHarness uses a bare fsnotify.Watcher rather than a real one: a
// real watcher's backend goroutine also writes to Events and Errors (the
// macOS backend does, even for a directory the test never touches) and would
// race with the test's own sends.
func newWatchLoopHarness(t *testing.T, s *pluginState, filename string) *fsnotify.Watcher {
	t.Helper()
	w := &fsnotify.Watcher{Events: make(chan fsnotify.Event), Errors: make(chan error)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.watchLoop(false, filename, w)
	}()

	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("watchLoop goroutine did not return after its channels closed")
		}
	})
	t.Cleanup(func() {
		close(w.Events)
		close(w.Errors)
	})

	return w
}

func TestWatchLoop(t *testing.T) {
	// The old loop ranged over watcher.Events only. Errors is unbuffered, so
	// the first error blocked fsnotify's writer forever and autorefresh
	// stopped dead with no warning at all.
	t.Run("an error is drained without blocking and a later event still reloads", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases.txt")
		require.NoError(t, os.WriteFile(path, []byte("aa:11:22:33:44:55 192.0.2.1\n"), 0o600))

		logPath := filepath.Join(dir, "watchloop.log")
		require.NoError(t, logger.WithFile(logPath))
		t.Cleanup(func() { _ = logger.WithFile(os.DevNull) })

		s := &pluginState{mode: keyMAC}
		w := newWatchLoopHarness(t, s, path)

		sent := make(chan struct{})
		go func() {
			w.Errors <- errors.New("simulated queue overflow")
			close(sent)
		}()
		select {
		case <-sent:
		case <-time.After(2 * time.Second):
			t.Fatal("send on watcher.Errors blocked: the loop is not draining the error channel")
		}

		require.Eventually(t, func() bool {
			data, err := os.ReadFile(logPath)
			return err == nil && strings.Contains(string(data), "watcher error for")
		}, time.Second, 10*time.Millisecond, "expected the watcher error to be logged")
		require.Eventually(t, func() bool { return s.numRecords() == 1 }, time.Second, 10*time.Millisecond,
			"an error must also trigger a reload")

		require.NoError(t, os.WriteFile(path,
			[]byte("aa:11:22:33:44:55 192.0.2.1\naa:11:22:33:44:66 192.0.2.2\n"), 0o600))
		w.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 2 }, time.Second, 10*time.Millisecond,
			"an event delivered after the error must still cause a reload")
	})

	t.Run("an event for a different file in the same directory is ignored", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases.txt")
		require.NoError(t, os.WriteFile(path, []byte("aa:11:22:33:44:55 192.0.2.1\n"), 0o600))

		s := &pluginState{mode: keyMAC}
		w := newWatchLoopHarness(t, s, path)

		w.Events <- fsnotify.Event{Name: filepath.Join(dir, "other.txt"), Op: fsnotify.Write}
		require.Never(t, func() bool { return s.numRecords() != 0 }, 200*time.Millisecond, 10*time.Millisecond,
			"an event for another file must not trigger a reload")

		w.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 1 }, time.Second, 10*time.Millisecond,
			"the loop must still react to the watched file after ignoring another one")
	})

	t.Run("an event for the watched file causes a reload", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases.txt")
		require.NoError(t, os.WriteFile(path, []byte("aa:11:22:33:44:55 192.0.2.1\n"), 0o600))

		s := &pluginState{mode: keyMAC}
		w := newWatchLoopHarness(t, s, path)

		w.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 1 }, time.Second, 10*time.Millisecond,
			"an event for the watched file must trigger a reload")
	})

	// A select on a closed channel spins at 100% CPU without the two-value
	// receive form. Each channel is closed separately so the select cannot
	// mask a bug by happening to pick the other, still-open case.
	for _, tc := range []struct {
		name  string
		close func(w *fsnotify.Watcher)
	}{
		{"closing Events makes the loop return", func(w *fsnotify.Watcher) { close(w.Events) }},
		{"closing Errors makes the loop return", func(w *fsnotify.Watcher) { close(w.Errors) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &pluginState{mode: keyMAC}
			path := filepath.Join(t.TempDir(), "leases.txt")
			w := &fsnotify.Watcher{Events: make(chan fsnotify.Event), Errors: make(chan error)}

			done := make(chan struct{})
			go func() {
				defer close(done)
				s.watchLoop(false, path, w)
			}()

			tc.close(w)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("watchLoop did not return after its channel closed")
			}
		})
	}
}

// TestParseArgs covers the config-line grammar directly: the required file
// name, the two optional arguments in either order, and the errors each bad
// input produces.
func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		v6       bool
		args     []string
		wantErr  string
		wantOpts options
	}{
		{name: "no arguments", wantErr: "need a file name"},
		{name: "empty file name", args: []string{""}, wantErr: "got empty file name"},
		{
			name:     "file name only defaults to mac",
			args:     []string{"leases.txt"},
			wantOpts: options{filename: "leases.txt", mode: keyMAC},
		},
		{
			name:     "autorefresh",
			args:     []string{"leases.txt", autoRefreshArg},
			wantOpts: options{filename: "leases.txt", autorefresh: true, mode: keyMAC},
		},
		{
			name:     "key:mac explicit",
			args:     []string{"leases.txt", "key:mac"},
			wantOpts: options{filename: "leases.txt", mode: keyMAC},
		},
		{
			name:     "key:duid on server6",
			v6:       true,
			args:     []string{"leases.txt", "key:duid"},
			wantOpts: options{filename: "leases.txt", mode: keyDUID},
		},
		{
			name:     "key:client-id on server4",
			args:     []string{"leases.txt", "key:client-id"},
			wantOpts: options{filename: "leases.txt", mode: keyClientID},
		},
		{
			name:     "autorefresh then key",
			v6:       true,
			args:     []string{"leases.txt", autoRefreshArg, "key:duid"},
			wantOpts: options{filename: "leases.txt", autorefresh: true, mode: keyDUID},
		},
		{
			name:     "key then autorefresh, reversed order",
			v6:       true,
			args:     []string{"leases.txt", "key:duid", autoRefreshArg},
			wantOpts: options{filename: "leases.txt", autorefresh: true, mode: keyDUID},
		},
		{name: "unknown argument", args: []string{"leases.txt", "bogus"}, wantErr: `unknown argument "bogus"`},
		{name: "unknown key value", args: []string{"leases.txt", "key:bogus"}, wantErr: `unknown key "bogus"`},
		{name: "key:duid rejected on server4", args: []string{"leases.txt", "key:duid"}, wantErr: "key:duid"},
		{
			name:    "key:client-id rejected on server6",
			v6:      true,
			args:    []string{"leases.txt", "key:client-id"},
			wantErr: "key:client-id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgs(tc.v6, tc.args)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOpts, got)
		})
	}
}
