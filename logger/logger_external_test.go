// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package logger_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
)

// These tests only use the exported API: they must leave global state as
// they found it, since they share a test binary with logger_internal_test.go.

func TestLevelsSorted(t *testing.T) {
	got := logger.Levels()
	want := []string{"debug", "error", "fatal", "info", "none", "warning"}
	assert.Equal(t, want, got)
}

func TestSetLevelValidAndInvalid(t *testing.T) {
	t.Cleanup(func() { _ = logger.SetLevel("info") })

	cases := []struct {
		name    string
		wantErr bool
	}{
		{"debug", false},
		{"DEBUG", false}, // names are case-insensitive
		{"Info", false},
		{"warning", false},
		{"error", false},
		{"fatal", false},
		{"none", false},
		{"unknown", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := logger.SetLevel(tc.name)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.name)
				for _, lvl := range logger.Levels() {
					assert.Contains(t, err.Error(), lvl)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestGetLoggerReturnsUsableLogger(t *testing.T) {
	for _, prefix := range []string{"", "blackbox"} {
		l := logger.GetLogger(prefix)
		require.NotNil(t, l)
		assert.NotPanics(t, func() { l.Info("hello") })
	}
}

func TestWithReturnsNewInstance(t *testing.T) {
	l := logger.GetLogger("withtest")
	l2 := l.With("a", "b")
	require.NotNil(t, l2)
	assert.NotSame(t, l, l2)
	assert.NotPanics(t, func() { l2.Warningf("hi %d", 1) })
}

func TestWithConsoleRedirectsOutput(t *testing.T) {
	t.Cleanup(func() {
		// Restores os.Stderr, the package's default console, for tests sharing this binary.
		logger.WithConsole(os.Stderr)
	})

	buf := &bytes.Buffer{}
	logger.WithConsole(buf)

	l := logger.GetLogger("test")
	l.Info("hello-from-external-test")

	assert.Contains(t, buf.String(), "hello-from-external-test")
}
