// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const alphaSource = "// Package alpha hands out widgets.\npackage alpha\n"

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/mod\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plugins", "alpha"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "plugins", "alpha", "doc.go"), []byte(alphaSource), 0o600))
	return root
}

func TestRunWritesThenChecksClean(t *testing.T) {
	root := fixture(t)

	err := run(root, true)
	require.Error(t, err, "nothing is committed yet, so -check has to fail")
	assert.Contains(t, err.Error(), "1 README(s) no longer match their package doc")
	assert.Contains(t, err.Error(), filepath.Join(root, "plugins", "alpha", "README.md"))
	assert.Contains(t, err.Error(), "go generate ./plugins/")
	assert.NoFileExists(t, filepath.Join(root, "plugins", "alpha", "README.md"), "-check writes nothing")

	require.NoError(t, run(root, false))
	assert.FileExists(t, filepath.Join(root, "plugins", "alpha", "README.md"))
	assert.NoError(t, run(root, true))
}

func TestRunReportsADriftedReadme(t *testing.T) {
	root := fixture(t)
	require.NoError(t, run(root, false))

	require.NoError(t, os.WriteFile(filepath.Join(root, "plugins", "alpha", "doc.go"),
		[]byte("// Package alpha hands out gadgets now.\npackage alpha\n"), 0o600))

	err := run(root, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 README(s) no longer match their package doc")
}

// TestRunPropagatesACheckError covers the case where -check cannot read a
// README at all, which is a different failure from one that drifted.
func TestRunPropagatesACheckError(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("file modes do not stop this user from reading")
	}
	root := fixture(t)
	require.NoError(t, run(root, false))

	readme := filepath.Join(root, "plugins", "alpha", "README.md")
	require.NoError(t, os.Chmod(readme, 0o000))
	t.Cleanup(func() { _ = os.Chmod(readme, 0o600) })

	err := run(root, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regenerate")
}

func TestRunFailsOnABadRoot(t *testing.T) {
	for _, check := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "check"}[check], func(t *testing.T) {
			err := run(filepath.Join(t.TempDir(), "absent"), check)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "point -root at the repository root")
		})
	}
}
