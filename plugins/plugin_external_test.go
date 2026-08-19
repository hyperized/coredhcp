// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugins_test

import (
	"errors"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
)

// register registers plugin for the lifetime of the test and removes it
// from the shared registry on cleanup, so tests stay order-independent as
// long as each one picks a unique plugin name.
func register(t *testing.T, plugin *plugins.Plugin) {
	t.Helper()
	require.NoError(t, plugins.RegisterPlugin(plugin))
	t.Cleanup(func() {
		delete(plugins.RegisteredPlugins, plugin.Name)
	})
}

func stubHandler6(_ ...string) (handler.Handler6, error) {
	return func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		return resp, false
	}, nil
}

func stubHandler4(_ ...string) (handler.Handler4, error) {
	return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		return resp, false
	}, nil
}

func failingSetup6(_ ...string) (handler.Handler6, error) {
	return nil, errors.New("setup6 boom")
}

func failingSetup4(_ ...string) (handler.Handler4, error) {
	return nil, errors.New("setup4 boom")
}

func nilHandlerSetup6(_ ...string) (handler.Handler6, error) {
	return nil, nil
}

func nilHandlerSetup4(_ ...string) (handler.Handler4, error) {
	return nil, nil
}

func TestLoadPluginsNoConfig(t *testing.T) {
	_, _, err := plugins.LoadPlugins(&config.Config{})
	assert.EqualError(t, err, "no configuration found for either DHCPv6 or DHCPv4")
}

func TestLoadPluginsUnknownPlugin(t *testing.T) {
	cases := []struct {
		name string
		conf *config.Config
		want string
	}{
		{
			name: "v6",
			conf: &config.Config{
				Server6: &config.ServerConfig{
					Plugins: []config.PluginConfig{{Name: "does-not-exist-v6"}},
				},
			},
			want: "DHCPv6: unknown plugin `does-not-exist-v6`",
		},
		{
			name: "v4",
			conf: &config.Config{
				Server4: &config.ServerConfig{
					Plugins: []config.PluginConfig{{Name: "does-not-exist-v4"}},
				},
			},
			want: "DHCPv4: unknown plugin `does-not-exist-v4`",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := plugins.LoadPlugins(tc.conf)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadPluginsNoSetupWarns(t *testing.T) {
	t.Run("v6 plugin has no Setup6", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-no-setup6", Setup4: stubHandler4}
		register(t, plugin)

		conf := &config.Config{
			Server6: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		handlers4, handlers6, err := plugins.LoadPlugins(conf)
		require.NoError(t, err)
		assert.Empty(t, handlers6)
		assert.Empty(t, handlers4)
	})

	t.Run("v4 plugin has no Setup4", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-no-setup4", Setup6: stubHandler6}
		register(t, plugin)

		conf := &config.Config{
			Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		handlers4, handlers6, err := plugins.LoadPlugins(conf)
		require.NoError(t, err)
		assert.Empty(t, handlers4)
		assert.Empty(t, handlers6)
	})
}

func TestLoadPluginsSetupError(t *testing.T) {
	t.Run("v6", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-setup6-error", Setup6: failingSetup6}
		register(t, plugin)

		conf := &config.Config{
			Server6: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		_, _, err := plugins.LoadPlugins(conf)
		assert.EqualError(t, err, "setup6 boom")
	})

	t.Run("v4", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-setup4-error", Setup4: failingSetup4}
		register(t, plugin)

		conf := &config.Config{
			Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		_, _, err := plugins.LoadPlugins(conf)
		assert.EqualError(t, err, "setup4 boom")
	})
}

func TestLoadPluginsNilHandler(t *testing.T) {
	t.Run("v6", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-nil-handler6", Setup6: nilHandlerSetup6}
		register(t, plugin)

		conf := &config.Config{
			Server6: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		_, _, err := plugins.LoadPlugins(conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no DHCPv6 handler for plugin test-nil-handler6")
	})

	t.Run("v4", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-nil-handler4", Setup4: nilHandlerSetup4}
		register(t, plugin)

		conf := &config.Config{
			Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			},
		}
		_, _, err := plugins.LoadPlugins(conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no DHCPv4 handler for plugin test-nil-handler4")
	})
}

func TestLoadPluginsSuccess(t *testing.T) {
	plugin := &plugins.Plugin{Name: "test-load-success", Setup6: stubHandler6, Setup4: stubHandler4}
	register(t, plugin)

	conf := &config.Config{
		Server6: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		},
		Server4: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		},
	}
	handlers4, handlers6, err := plugins.LoadPlugins(conf)
	require.NoError(t, err)
	assert.Len(t, handlers6, 1)
	assert.Len(t, handlers4, 1)
}
