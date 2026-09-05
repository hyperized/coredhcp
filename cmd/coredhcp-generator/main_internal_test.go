// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"bufio"
	"bytes"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flag "github.com/spf13/pflag"
)

// tuiTemplateFile is the second template the build renders, with -t. It is
// not a default anywhere in the generator, so the tests name it themselves.
const tuiTemplateFile = "coredhcp-tui.go.template"

// withGeneratorFlags sets the pflag values run() reads, restoring them after.
// pluginArgs must be plain tokens with no dashes: that's the only way to set positional names.
func withGeneratorFlags(t *testing.T, tmpl, outfile, fromFile string, pluginArgs []string) {
	t.Helper()
	origTmpl, origOut, origFrom := *flagTemplate, *flagOutfile, *flagFromFile
	*flagTemplate = tmpl
	*flagOutfile = outfile
	*flagFromFile = fromFile
	require.NoError(t, flag.CommandLine.Parse(pluginArgs))
	t.Cleanup(func() {
		*flagTemplate = origTmpl
		*flagOutfile = origOut
		*flagFromFile = origFrom
		_ = flag.CommandLine.Parse(nil)
	})
}

// The only way to learn where a tempdir output file landed: run() prints just
// the directory.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func TestRunTemplateMissing(t *testing.T) {
	withGeneratorFlags(t, filepath.Join(t.TempDir(), "does-not-exist.template"), "", "", nil)
	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read template file")
}

func TestRunTemplateParseError(t *testing.T) {
	withGeneratorFlags(t, "testdata/broken-parse.go.template", "", "", nil)
	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template parsing failed")
}

func TestRunNoPluginsSpecified(t *testing.T) {
	withGeneratorFlags(t, defaultTemplateFile, "", "", nil)
	err := run()
	require.Error(t, err)
	assert.EqualError(t, err, "no plugin specified")
}

// The render is also compared against gofmt's own output: the generator neither
// formats nor compiles what it writes, and CI regenerates both mains and fails on any diff.
func TestRunBarePluginNamesAndFullImportPaths(t *testing.T) {
	for _, tc := range []struct{ name, template string }{
		{name: "coredhcp", template: defaultTemplateFile},
		{name: "coredhcp-tui", template: tuiTemplateFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "generated.go")
			// Blank and whitespace-only entries exercise the TrimSpace + skip-if-empty branch.
			withGeneratorFlags(t, tc.template, outPath, "", []string{"", "   ", "serverid", "github.com/example/custom"})

			err := run()
			require.NoError(t, err)

			content, err := os.ReadFile(outPath)
			require.NoError(t, err)
			got := string(content)
			assert.Contains(t, got, `pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"`)
			assert.Contains(t, got, `pl_custom "github.com/example/custom"`)

			_, err = parser.ParseFile(token.NewFileSet(), outPath, content, parser.AllErrors)
			require.NoError(t, err, "rendered output is not valid Go")

			formatted, err := format.Source(content)
			require.NoError(t, err)
			assert.Equal(t, string(formatted), got, "rendered output is not gofmt-clean")
		})
	}
}

func TestRunFromFileValidWithBlankLines(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "generated.go")
	withGeneratorFlags(t, defaultTemplateFile, outPath, "testdata/from-plugins.txt", nil)

	err := run()
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	got := string(content)
	assert.Contains(t, got, `pl_pluginA "github.com/example/pluginA"`)
	assert.Contains(t, got, `pl_pluginB "github.com/example/pluginB"`)
}

func TestRunFromFileMissing(t *testing.T) {
	withGeneratorFlags(t, defaultTemplateFile, "", filepath.Join(t.TempDir(), "nope.txt"), []string{"serverid"})
	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read file")
}

// The fixture is generated rather than committed to testdata/, since it must
// exceed bufio.MaxScanTokenSize (64KiB) on a single line.
func TestRunFromFileScannerError(t *testing.T) {
	dir := t.TempDir()
	fromPath := filepath.Join(dir, "huge-line.txt")
	longLine := strings.Repeat("a", bufio.MaxScanTokenSize+1024)
	require.NoError(t, os.WriteFile(fromPath, []byte(longLine), 0o600))

	withGeneratorFlags(t, defaultTemplateFile, "", fromPath, nil)
	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file")
}

func TestRunTemplateExecutionError(t *testing.T) {
	withGeneratorFlags(t, "testdata/broken-execute.go.template", "", "", []string{"serverid"})
	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template execution failed")
}

func TestRunOutfileDefaultsToTempdir(t *testing.T) {
	withGeneratorFlags(t, defaultTemplateFile, "", "", []string{"serverid"})

	var runErr error
	printed := captureStdout(t, func() {
		runErr = run()
	})
	require.NoError(t, runErr)

	dir := strings.TrimSpace(printed)
	require.NotEmpty(t, dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	content, err := os.ReadFile(filepath.Join(dir, "coredhcp.go"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "pl_serverid")
}

func TestRunTempdirCreationError(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
	withGeneratorFlags(t, defaultTemplateFile, "", "", []string{"serverid"})

	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create temporary directory")
}

func TestRunOutfileOpenError(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "no-such-subdir", "generated.go")
	withGeneratorFlags(t, defaultTemplateFile, outPath, "", []string{"serverid"})

	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create output file")
}

// usage() is otherwise reached only via flag.Usage on a parse error, which would
// exit the process, so this test calls it directly instead.
func TestUsageDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, usage)
}
