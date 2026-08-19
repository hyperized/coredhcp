// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
)

func TestLoadWithExplicitPath(t *testing.T) {
	t.Run("both servers configured", func(t *testing.T) {
		c, err := config.Load("testdata/valid_both.yml")
		require.NoError(t, err)
		require.NotNil(t, c)
		assert.NotNil(t, c.Server6)
		assert.NotNil(t, c.Server4)
	})

	t.Run("v6 only", func(t *testing.T) {
		c, err := config.Load("testdata/valid_v6_only.yml")
		require.NoError(t, err)
		require.NotNil(t, c)
		assert.NotNil(t, c.Server6)
		assert.Nil(t, c.Server4)
	})

	t.Run("v4 only", func(t *testing.T) {
		c, err := config.Load("testdata/valid_v4_only.yml")
		require.NoError(t, err)
		require.NotNil(t, c)
		assert.Nil(t, c.Server6)
		assert.NotNil(t, c.Server4)
	})

	t.Run("nonexistent path fails to read", func(t *testing.T) {
		_, err := config.Load("testdata/does-not-exist.yml")
		require.Error(t, err)
	})

	t.Run("no server6 or server4 section is an error", func(t *testing.T) {
		_, err := config.Load("testdata/no_servers.yml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "need at least one valid config")
	})

	t.Run("invalid server6 plugins section fails while parsing v6", func(t *testing.T) {
		_, err := config.Load("testdata/bad_plugins_v6.yml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid plugins section")
	})

	t.Run("invalid server4 plugins section fails while parsing v4", func(t *testing.T) {
		_, err := config.Load("testdata/bad_plugins_v4.yml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid plugins section")
	})
}

func TestLoadWithDefaultSearchPath(t *testing.T) {
	dir := t.TempDir()
	content, err := os.ReadFile("testdata/valid_v4_only.yml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), content, 0o600))

	t.Chdir(dir)

	c, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NotNil(t, c.Server4)
	assert.Nil(t, c.Server6)
}

func TestError(t *testing.T) {
	e := config.ErrorFromString("boom %d", 42)
	require.Error(t, e)
	assert.EqualError(t, e, "error parsing config: boom 42")
}

func TestErrorFromError(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := config.ErrorFromError(sentinel)
	assert.EqualError(t, e, "error parsing config: sentinel")
}

func TestErrorUnwrap(t *testing.T) {
	inner := errors.New("inner")
	e := config.ErrorFromError(inner)
	assert.Same(t, inner, errors.Unwrap(e))
}

func TestErrorIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := config.ErrorFromError(fmt.Errorf("wrapped: %w", sentinel))
	assert.True(t, errors.Is(e, sentinel))
}

// wrappedErr is a concrete error type used to prove that errors.As can see
// through config.Error via its Unwrap method.
type wrappedErr struct{ msg string }

func (w *wrappedErr) Error() string { return w.msg }

func TestErrorAs(t *testing.T) {
	inner := &wrappedErr{msg: "inner"}
	e := config.ErrorFromError(fmt.Errorf("wrapped: %w", inner))

	var target *wrappedErr
	require.True(t, errors.As(e, &target))
	assert.Same(t, inner, target)
}
