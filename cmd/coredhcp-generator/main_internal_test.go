// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flag "github.com/spf13/pflag"
)

// withGeneratorFlags sets the package-level pflag values run() reads,
// restoring the previous values afterwards. Positional plugin names can
// only be set through flag.CommandLine.Parse (there is no pointer for
// them), so pluginArgs must contain plain tokens with no leading dashes.
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

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. run() prints the generated file's directory
// with fmt.Println when -o is not given, and that is the only way to learn
// where a tempdir-derived output file landed.
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

// TestRunBarePluginNamesAndFullImportPaths covers: bare plugin names
// getting the importBase prefix, full import paths passed through
// unchanged, an explicit -o outfile, and the real template rendering
// imports for both.
//
// A bare builtin name like "serverid" expands to the real package path
// "github.com/coredhcp/coredhcp/plugins/serverid". This shortcut was broken
// until recently (it expanded to .../coredhcp/serverid), which is why every
// documented usage only ever passed full paths.
func TestRunBarePluginNamesAndFullImportPaths(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "generated.go")
	// The blank and whitespace-only entries exercise the
	// strings.TrimSpace + skip-if-empty branch for positional args.
	withGeneratorFlags(t, defaultTemplateFile, outPath, "", []string{"", "   ", "serverid", "github.com/example/custom"})

	err := run()
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	got := string(content)
	assert.Contains(t, got, `pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"`)
	assert.Contains(t, got, `pl_custom "github.com/example/custom"`)
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

// TestRunFromFileScannerError drives bufio.Scanner past its default token
// limit so sc.Err() returns non-nil after the scan loop. The fixture is
// generated rather than committed to testdata/, since it must exceed
// bufio.MaxScanTokenSize (64KiB) on a single line.
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

// TestRunOutfileDefaultsToTempdir covers the -o-omitted path: run() creates
// its own tempdir and prints its path to stdout.
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

// TestRunTempdirCreationError drives the os.MkdirTemp error branch by
// pointing TMPDIR at a path that does not exist.
func TestRunTempdirCreationError(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
	withGeneratorFlags(t, defaultTemplateFile, "", "", []string{"serverid"})

	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create temporary directory")
}

// TestRunOutfileOpenError drives the os.OpenFile error branch: the parent
// directory of the requested -o path does not exist.
func TestRunOutfileOpenError(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "no-such-subdir", "generated.go")
	withGeneratorFlags(t, defaultTemplateFile, outPath, "", []string{"serverid"})

	err := run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create output file")
}

// TestUsageDoesNotPanic covers usage(), which is otherwise only reached via
// flag.Usage on a parse error (e.g. -h), a path this suite never exercises
// because it would exit the process.
func TestUsageDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, usage)
}
