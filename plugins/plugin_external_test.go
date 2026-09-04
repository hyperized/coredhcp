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

func TestLoadChainsNoConfig(t *testing.T) {
	chains, err := plugins.LoadChains(&config.Config{})
	assert.Nil(t, chains)
	assert.EqualError(t, err, "no configuration found for either DHCPv6 or DHCPv4")
}

// The chain records the plugin each handler came from, in configuration
// order. A plugin without a setup function for the family is skipped, so the
// chain is shorter than the configured list and the positions shift.
func TestLoadChainsNamesInChainOrder(t *testing.T) {
	both := &plugins.Plugin{Name: "test-chain-both", Setup6: stubHandler6, Setup4: stubHandler4}
	v4only := &plugins.Plugin{Name: "test-chain-v4-only", Setup4: stubHandler4}
	register(t, both)
	register(t, v4only)

	conf := &config.Config{
		Server6: &config.ServerConfig{
			Plugins: []config.PluginConfig{
				{Name: v4only.Name},
				{Name: both.Name, Args: []string{"six"}},
			},
		},
		Server4: &config.ServerConfig{
			Plugins: []config.PluginConfig{
				{Name: both.Name, Args: []string{"four", "args"}},
				{Name: v4only.Name},
			},
		},
	}

	chains, err := plugins.LoadChains(conf)
	require.NoError(t, err)
	require.NotNil(t, chains)

	require.Len(t, chains.V6, 1)
	assert.Equal(t, both.Name, chains.V6[0].Name)
	assert.Equal(t, []string{"six"}, chains.V6[0].Args)
	assert.NotNil(t, chains.V6[0].Handler)

	require.Len(t, chains.V4, 2)
	assert.Equal(t, both.Name, chains.V4[0].Name)
	assert.Equal(t, []string{"four", "args"}, chains.V4[0].Args)
	assert.Equal(t, v4only.Name, chains.V4[1].Name)
	assert.Nil(t, chains.V4[1].Args)
}

// Only the configured family gets a chain; the other one stays nil.
func TestLoadChainsSingleFamily(t *testing.T) {
	plugin := &plugins.Plugin{Name: "test-chain-single", Setup6: stubHandler6, Setup4: stubHandler4}
	register(t, plugin)

	cases := []struct {
		name   string
		conf   *config.Config
		wantV4 int
		wantV6 int
	}{
		{
			name: "v6 only",
			conf: &config.Config{Server6: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			}},
			wantV6: 1,
		},
		{
			name: "v4 only",
			conf: &config.Config{Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: plugin.Name}},
			}},
			wantV4: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains, err := plugins.LoadChains(tc.conf)
			require.NoError(t, err)
			assert.Len(t, chains.V4, tc.wantV4)
			assert.Len(t, chains.V6, tc.wantV6)
		})
	}
}

func TestLoadChainsErrors(t *testing.T) {
	register(t, &plugins.Plugin{Name: "test-chain-setup6-error", Setup6: failingSetup6})
	register(t, &plugins.Plugin{Name: "test-chain-setup4-error", Setup4: failingSetup4})

	cases := []struct {
		name string
		conf *config.Config
		want string
	}{
		{
			name: "unknown plugin",
			conf: &config.Config{Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: "test-chain-does-not-exist"}},
			}},
			want: "DHCPv4: unknown plugin `test-chain-does-not-exist`",
		},
		{
			name: "v6 setup fails",
			conf: &config.Config{Server6: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: "test-chain-setup6-error"}},
			}},
			want: "setup6 boom",
		},
		{
			name: "v4 setup fails",
			conf: &config.Config{Server4: &config.ServerConfig{
				Plugins: []config.PluginConfig{{Name: "test-chain-setup4-error"}},
			}},
			want: "setup4 boom",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains, err := plugins.LoadChains(tc.conf)
			require.Error(t, err)
			assert.Nil(t, chains)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Args in a link are a copy: rewriting the configuration afterwards does not
// reach into a chain that is already loaded.
func TestLoadChainsCopiesArgs(t *testing.T) {
	plugin := &plugins.Plugin{Name: "test-chain-args", Setup4: stubHandler4}
	register(t, plugin)

	args := []string{"original"}
	conf := &config.Config{Server4: &config.ServerConfig{
		Plugins: []config.PluginConfig{{Name: plugin.Name, Args: args}},
	}}

	chains, err := plugins.LoadChains(conf)
	require.NoError(t, err)
	args[0] = "rewritten"

	require.Len(t, chains.V4, 1)
	assert.Equal(t, []string{"original"}, chains.V4[0].Args)
}
