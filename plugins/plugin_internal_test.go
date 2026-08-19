// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugins

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerCleanup registers plugin under a unique name and removes it from
// RegisteredPlugins once the test completes, so tests stay order-independent
// without having to save and restore the whole registry.
func registerCleanup(t *testing.T, plugin *Plugin) {
	t.Helper()
	require.NoError(t, RegisterPlugin(plugin))
	t.Cleanup(func() {
		delete(RegisteredPlugins, plugin.Name)
	})
}

func TestRegisterPluginNil(t *testing.T) {
	err := RegisterPlugin(nil)
	assert.EqualError(t, err, "cannot register nil plugin")
}

func TestRegisterPluginSuccess(t *testing.T) {
	plugin := &Plugin{Name: "test-register-success"}
	registerCleanup(t, plugin)

	got, ok := RegisteredPlugins[plugin.Name]
	require.True(t, ok)
	assert.Same(t, plugin, got)
}

func TestRegisterPluginDuplicatePanics(t *testing.T) {
	plugin := &Plugin{Name: "test-register-duplicate"}
	registerCleanup(t, plugin)

	assert.PanicsWithValue(t,
		"Plugin 'test-register-duplicate' is already registered",
		func() {
			_ = RegisterPlugin(plugin)
		},
	)
}
