// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
