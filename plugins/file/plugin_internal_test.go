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
