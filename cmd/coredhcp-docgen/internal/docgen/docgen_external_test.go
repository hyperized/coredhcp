// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package docgen_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/cmd/coredhcp-docgen/internal/docgen"
)

const goMod = "module example.test/mod\n\ngo 1.27\n"

const alphaSource = `// Package alpha hands out widgets.
//
// # Configuration
//
// One widget per line.
package alpha
`

const alphaREADME = docgen.Header + `

# example.test/mod/plugins/alpha

Package alpha hands out widgets.

## Configuration

One widget per line.
`

// tree writes files, named by their slash-separated path below a fresh
// temporary directory, and returns that directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return root
}

func paths(readmes []docgen.README) []string {
	out := make([]string, 0, len(readmes))
	for _, r := range readmes {
		out = append(out, r.Path)
	}
	return out
}

func TestRender(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":                 goMod,
		"plugins/alpha/doc.go":   alphaSource,
		"plugins/alpha/thing.go": "package alpha\n\nfunc thing() {}\n",
	})

	readmes, err := docgen.Render(root)
	require.NoError(t, err)
	require.Len(t, readmes, 1)

	assert.Equal(t, filepath.Join(root, "plugins", "alpha", "README.md"), readmes[0].Path)
	assert.Equal(t, "example.test/mod/plugins/alpha", readmes[0].ImportPath)
	assert.Equal(t, alphaREADME, string(readmes[0].Content))
}

// TestRenderHeadings pins the two printer settings that decide how the
// rendered file reads on GitHub: doc sections sit one level under the title,
// and no "{#hdr-...}" anchor, which GitHub would show as text, is emitted.
func TestRenderHeadings(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":              goMod,
		"plugins/beta/doc.go": "// Package beta is a plugin.\n//\n// # Placement\n//\n// Last.\npackage beta\n",
	})

	readmes, err := docgen.Render(root)
	require.NoError(t, err)
	require.Len(t, readmes, 1)

	body := string(readmes[0].Content)
	assert.Contains(t, body, "\n# example.test/mod/plugins/beta\n")
	assert.Contains(t, body, "\n## Placement\n")
	assert.NotContains(t, body, "{#")
}

func TestRenderWhichDirectories(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":                            goMod,
		"plugins/plugin.go":                 "// Package plugins is the registry.\npackage plugins\n",
		"plugins/alpha/doc.go":              alphaSource,
		"plugins/alpha/sub/doc.go":          "// Package sub is nested.\npackage sub\n",
		"plugins/internal/helper/helper.go": "// Package helper is not a plugin.\npackage helper\n",
		"plugins/alpha/testdata/fixture.go": "package fixture\n",
		"plugins/notapackage/readme.txt":    "no Go here",
		"plugins/testsonly/plugin_test.go":  "package testsonly\n",
		"plugins/.scratch/doc.go":           "// Package scratch is a leftover.\npackage scratch\n",
		"plugins/_ignored/doc.go":           "// Package ignored is a leftover.\npackage ignored\n",
		"cmd/tool/main.go":                  "package main\n",
	})

	readmes, err := docgen.Render(root)
	require.NoError(t, err)

	assert.Equal(t, []string{
		filepath.Join(root, "plugins", "README.md"),
		filepath.Join(root, "plugins", "alpha", "README.md"),
		filepath.Join(root, "plugins", "alpha", "sub", "README.md"),
	}, paths(readmes))
}

func TestWriteThenDiffering(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":               goMod,
		"plugins/alpha/doc.go": alphaSource,
	})
	readmes, err := docgen.Render(root)
	require.NoError(t, err)

	stale, err := docgen.Differing(readmes)
	require.NoError(t, err)
	assert.Equal(t, paths(readmes), stale, "a README that was never written counts as stale")

	require.NoError(t, docgen.Write(readmes))
	stale, err = docgen.Differing(readmes)
	require.NoError(t, err)
	assert.Empty(t, stale)

	written, err := os.ReadFile(readmes[0].Path)
	require.NoError(t, err)
	assert.Equal(t, alphaREADME, string(written))

	require.NoError(t, os.WriteFile(readmes[0].Path, []byte("hand edited\n"), 0o600))
	stale, err = docgen.Differing(readmes)
	require.NoError(t, err)
	assert.Equal(t, paths(readmes), stale)
}

// TestWriteIsIdempotent pins that a second run over an unchanged tree
// produces the same bytes, which is what makes the -check step in CI mean
// anything.
func TestWriteIsIdempotent(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":               goMod,
		"plugins/alpha/doc.go": alphaSource,
		"plugins/beta/doc.go":  "// Package beta is a plugin.\npackage beta\n",
	})
	first, err := docgen.Render(root)
	require.NoError(t, err)
	require.NoError(t, docgen.Write(first))

	second, err := docgen.Render(root)
	require.NoError(t, err)
	require.NoError(t, docgen.Write(second))

	assert.Equal(t, first, second)
	stale, err := docgen.Differing(second)
	require.NoError(t, err)
	assert.Empty(t, stale)
}

func TestRenderErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		errText string
	}{
		{
			name:    "no go.mod",
			files:   map[string]string{"plugins/alpha/doc.go": alphaSource},
			errText: "point -root at the repository root",
		},
		{
			name:    "go.mod without a module line",
			files:   map[string]string{"go.mod": "go 1.27\n", "plugins/alpha/doc.go": alphaSource},
			errText: "has to declare one",
		},
		{
			name:    "no plugins directory",
			files:   map[string]string{"go.mod": goMod},
			errText: "cannot walk",
		},
		{
			name:    "a plugin that does not parse",
			files:   map[string]string{"go.mod": goMod, "plugins/alpha/doc.go": "package alpha\nfunc (\n"},
			errText: "fix the syntax error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := docgen.Render(tree(t, tc.files))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errText)
		})
	}
}

func TestWriteError(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":               goMod,
		"plugins/alpha/doc.go": alphaSource,
	})
	readmes, err := docgen.Render(root)
	require.NoError(t, err)

	dir := filepath.Join(root, "plugins", "alpha")
	requireUnwritable(t, dir)

	err = docgen.Write(readmes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is writable")
}

// requireUnwritable takes the write bit off dir for the rest of the test.
// Running as root ignores the mode, so the tests that need a failing write
// skip instead of asserting something that cannot happen.
func requireUnwritable(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("file modes do not stop this user from writing")
	}
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, info.Mode().Perm()) })
}
