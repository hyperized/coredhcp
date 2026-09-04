// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugins

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
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

// newLink4 and newLink6 copy the configured arguments. The link is kept for
// the life of the server, so it must not alias a slice the caller can still
// write to.
func TestNewLinkCopiesArgs(t *testing.T) {
	args := []string{"first", "second"}

	l4 := newLink4(config.PluginConfig{Name: "copy-4", Args: args}, func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		return resp, false
	})
	l6 := newLink6(config.PluginConfig{Name: "copy-6", Args: args}, func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		return resp, false
	})
	args[0] = "mutated"

	assert.Equal(t, "copy-4", l4.Name)
	assert.Equal(t, []string{"first", "second"}, l4.Args)
	assert.NotNil(t, l4.Handler)

	assert.Equal(t, "copy-6", l6.Name)
	assert.Equal(t, []string{"first", "second"}, l6.Args)
	assert.NotNil(t, l6.Handler)
}

// A plugin configured without arguments gets a nil Args, not an empty slice,
// so an observer can tell "no arguments" from "one empty argument".
func TestNewLinkWithoutArgs(t *testing.T) {
	l4 := newLink4(config.PluginConfig{Name: "no-args-4"}, nil)
	l6 := newLink6(config.PluginConfig{Name: "no-args-6"}, nil)
	assert.Nil(t, l4.Args)
	assert.Nil(t, l6.Args)
}
