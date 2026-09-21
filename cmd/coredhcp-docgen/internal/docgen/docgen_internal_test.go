// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package docgen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkipDir(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name: "range", want: false},
		{name: "allocators", want: false},
		{name: "internal", want: true},
		{name: "testdata", want: true},
		{name: ".git", want: true},
		{name: "_scratch", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, skipDir(tc.name))
		})
	}
}

func TestModulePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
		errText string
	}{
		{name: "plain", content: "module example.test/mod\n\ngo 1.27\n", want: "example.test/mod"},
		{name: "no trailing newline", content: "module example.test/mod", want: "example.test/mod"},
		{name: "indented", content: "go 1.27\n  module example.test/mod\n", want: "example.test/mod"},
		{name: "no module line", content: "go 1.27\n", errText: "has to declare one"},
		{name: "a module-ish word only", content: "modules are nice\n", errText: "has to declare one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte(tc.content), 0o600))

			got, err := modulePath(root)
			if tc.errText != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestBuildDocRejectsAForeignFileSet covers the one error doc.NewFromFiles
// still returns once the caller has filtered the file names: a file parsed
// into another file set has no position the doc builder can resolve.
func TestBuildDocRejectsAForeignFileSet(t *testing.T) {
	parsed := token.NewFileSet()
	f, err := parser.ParseFile(parsed, "doc.go", "// Package alpha is a plugin.\npackage alpha\n", parser.ParseComments)
	require.NoError(t, err)

	_, err = buildDoc(token.NewFileSet(), []*ast.File{f}, "example.test/mod/plugins/alpha")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has to parse as one package")
}

// TestMarkdownWithoutADoc pins what a package with no doc comment renders to:
// the header and the title, and no stray blank lines behind them.
func TestMarkdownWithoutADoc(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plugin.go"), []byte("package alpha\n"), 0o600))

	pkg, err := parsePackage(dir, "example.test/mod/plugins/alpha")
	require.NoError(t, err)
	assert.Equal(t, Header+"\n\n# example.test/mod/plugins/alpha\n", string(markdown(pkg, "example.test/mod/plugins/alpha")))
}

func TestRenderDirOutsideRoot(t *testing.T) {
	_, err := renderDir(t.TempDir(), "plugins/alpha", "example.test/mod")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "give -root a path")
}

func TestUnreadableDirectories(t *testing.T) {
	dir := requireUnreadableDir(t)

	t.Run("hasGoFiles", func(t *testing.T) {
		_, err := hasGoFiles(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fix the permissions")
	})

	t.Run("parsePackage", func(t *testing.T) {
		_, err := parsePackage(dir, "example.test/mod/plugins/alpha")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fix the permissions")
	})
}

func TestIsCurrentReadError(t *testing.T) {
	dir := requireUnreadableDir(t)

	_, err := isCurrent(README{Path: filepath.Join(dir, "README.md")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regenerate")
}

func TestDifferingPropagatesReadErrors(t *testing.T) {
	dir := requireUnreadableDir(t)

	_, err := Differing([]README{{Path: filepath.Join(dir, "README.md")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regenerate")
}

// requireUnreadableDir returns a directory this process may not list. Running
// as root ignores the mode, so a test that needs the failure skips rather
// than asserting something that cannot happen there.
func requireUnreadableDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("file modes do not stop this user from reading")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(dir, 0o750))
	require.NoError(t, os.Chmod(dir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	return dir
}
