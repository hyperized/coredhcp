// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugins_test

import (
	"context"
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

// register keeps tests order-independent, provided each picks a unique plugin name.
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

// The chain records each plugin in configuration order, but skips one with no
// setup function for the family, so the chain is shorter and positions shift.
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

// Refused outright, rather than picking one form and quietly ignoring the other.
func TestRegisterPluginConflictingSetup(t *testing.T) {
	cases := []struct {
		name   string
		plugin *plugins.Plugin
		family string
	}{
		{
			name: "DHCPv4",
			plugin: &plugins.Plugin{
				Name:      "test-conflict-v4",
				Setup4:    stubHandler4,
				Setup4Ctx: func(_ ...string) (handler.Handler4Ctx, error) { return nil, nil },
			},
			family: "DHCPv4",
		},
		{
			name: "DHCPv6",
			plugin: &plugins.Plugin{
				Name:      "test-conflict-v6",
				Setup6:    stubHandler6,
				Setup6Ctx: func(_ ...string) (handler.Handler6Ctx, error) { return nil, nil },
			},
			family: "DHCPv6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := plugins.RegisterPlugin(tc.plugin)
			require.Error(t, err)
			assert.ErrorIs(t, err, plugins.ErrConflictingSetup)
			assert.Contains(t, err.Error(), tc.plugin.Name)
			assert.Contains(t, err.Error(), tc.family)

			_, ok := plugins.RegisteredPlugins[tc.plugin.Name]
			assert.False(t, ok, "a plugin that failed to register must not end up in the registry")
		})
	}
}

// Reading the RequestInfo back off the context is the whole reason Setup4Ctx
// and Setup6Ctx exist.
func TestLoadChainsContextAwarePlugin(t *testing.T) {
	var gotV4, gotV6 handler.RequestInfo
	ctxPlugin := &plugins.Plugin{
		Name: "test-ctx-aware",
		Setup4Ctx: func(_ ...string) (handler.Handler4Ctx, error) {
			return func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				gotV4, _ = handler.RequestInfoFrom(ctx)
				return resp, false
			}, nil
		},
		Setup6Ctx: func(_ ...string) (handler.Handler6Ctx, error) {
			return func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
				gotV6, _ = handler.RequestInfoFrom(ctx)
				return resp, false
			}, nil
		},
	}
	plainSibling := &plugins.Plugin{Name: "test-ctx-aware-plain-sibling", Setup4: stubHandler4, Setup6: stubHandler6}
	register(t, ctxPlugin)
	register(t, plainSibling)

	conf := &config.Config{
		Server4: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plainSibling.Name}, {Name: ctxPlugin.Name}},
		},
		Server6: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plainSibling.Name}, {Name: ctxPlugin.Name}},
		},
	}
	chains, err := plugins.LoadChains(conf)
	require.NoError(t, err)

	require.Len(t, chains.V4, 2)
	assert.False(t, chains.V4[0].WantsContext)
	assert.True(t, chains.V4[1].WantsContext)
	require.NotNil(t, chains.V4[1].Handler)

	require.Len(t, chains.V6, 2)
	assert.False(t, chains.V6[0].WantsContext)
	assert.True(t, chains.V6[1].WantsContext)
	require.NotNil(t, chains.V6[1].Handler)

	// One link in each chain wants a context, so the chain as a whole does,
	// even though its sibling link ignores whatever it is handed.
	assert.True(t, plugins.WantsContext(chains.V4))
	assert.True(t, plugins.WantsContext(chains.V6))

	info := handler.RequestInfo{Interface: "eth0"}
	ctx := handler.WithRequestInfo(context.Background(), info)

	_, stop4 := chains.V4[1].Handler(ctx, nil, nil)
	assert.False(t, stop4)
	assert.Equal(t, info, gotV4)

	_, stop6 := chains.V6[1].Handler(ctx, nil, nil)
	assert.False(t, stop6)
	assert.Equal(t, info, gotV6)
}

// A plain handler was never written to expect a context, so the adapter around
// it swallows one.
func TestLoadChainsPlainPluginIgnoresContext(t *testing.T) {
	plugin := &plugins.Plugin{Name: "test-plain-only", Setup4: stubHandler4, Setup6: stubHandler6}
	register(t, plugin)

	conf := &config.Config{
		Server4: &config.ServerConfig{Plugins: []config.PluginConfig{{Name: plugin.Name}}},
		Server6: &config.ServerConfig{Plugins: []config.PluginConfig{{Name: plugin.Name}}},
	}
	chains, err := plugins.LoadChains(conf)
	require.NoError(t, err)

	require.Len(t, chains.V4, 1)
	assert.False(t, chains.V4[0].WantsContext)
	require.Len(t, chains.V6, 1)
	assert.False(t, chains.V6[0].WantsContext)
	assert.False(t, plugins.WantsContext(chains.V4))
	assert.False(t, plugins.WantsContext(chains.V6))

	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth0"})

	resp4, stop4 := chains.V4[0].Handler(ctx, nil, nil)
	assert.False(t, stop4)
	assert.Nil(t, resp4)

	resp6, stop6 := chains.V6[0].Handler(ctx, nil, nil)
	assert.False(t, stop6)
	assert.Nil(t, resp6)
}

func TestWantsContextEmptyChain(t *testing.T) {
	cases := []struct {
		name string
		v4   []plugins.Link4
		v6   []plugins.Link6
	}{
		{name: "nil chain", v4: nil, v6: nil},
		{name: "empty chain", v4: []plugins.Link4{}, v6: []plugins.Link6{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, plugins.WantsContext(tc.v4))
			assert.False(t, plugins.WantsContext(tc.v6))
		})
	}
}

// The legacy LoadPlugins path runs handlers on context.Background(), so
// RequestInfoFrom reports false.
func TestLoadPluginsContextAwarePluginSeesNoRequestInfo(t *testing.T) {
	var sawV4, sawV6 bool
	plugin := &plugins.Plugin{
		Name: "test-loadplugins-ctx-aware",
		Setup4Ctx: func(_ ...string) (handler.Handler4Ctx, error) {
			return func(ctx context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				_, sawV4 = handler.RequestInfoFrom(ctx)
				return resp, false
			}, nil
		},
		Setup6Ctx: func(_ ...string) (handler.Handler6Ctx, error) {
			return func(ctx context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
				_, sawV6 = handler.RequestInfoFrom(ctx)
				return resp, false
			}, nil
		},
	}
	register(t, plugin)

	conf := &config.Config{
		Server4: &config.ServerConfig{Plugins: []config.PluginConfig{{Name: plugin.Name}}},
		Server6: &config.ServerConfig{Plugins: []config.PluginConfig{{Name: plugin.Name}}},
	}
	handlers4, handlers6, err := plugins.LoadPlugins(conf)
	require.NoError(t, err)
	require.Len(t, handlers4, 1)
	require.Len(t, handlers6, 1)

	resp4, stop4 := handlers4[0](nil, nil)
	assert.False(t, stop4)
	assert.Nil(t, resp4)
	assert.False(t, sawV4)

	resp6, stop6 := handlers6[0](nil, nil)
	assert.False(t, stop6)
	assert.Nil(t, resp6)
	assert.False(t, sawV6)
}

func TestLoadChainsSetupCtxError(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-chain-setup4ctx-error", Setup4Ctx: func(_ ...string) (handler.Handler4Ctx, error) {
			return nil, errors.New("setup4ctx boom")
		}}
		register(t, plugin)

		conf := &config.Config{Server4: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		}}
		chains, err := plugins.LoadChains(conf)
		assert.Nil(t, chains)
		assert.EqualError(t, err, "setup4ctx boom")
	})

	t.Run("v6", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-chain-setup6ctx-error", Setup6Ctx: func(_ ...string) (handler.Handler6Ctx, error) {
			return nil, errors.New("setup6ctx boom")
		}}
		register(t, plugin)

		conf := &config.Config{Server6: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		}}
		chains, err := plugins.LoadChains(conf)
		assert.Nil(t, chains)
		assert.EqualError(t, err, "setup6ctx boom")
	})
}

func TestLoadChainsNilHandlerCtx(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-chain-nil-handler4ctx", Setup4Ctx: func(_ ...string) (handler.Handler4Ctx, error) {
			return nil, nil
		}}
		register(t, plugin)

		conf := &config.Config{Server4: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		}}
		chains, err := plugins.LoadChains(conf)
		assert.Nil(t, chains)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no DHCPv4 handler for plugin test-chain-nil-handler4ctx")
	})

	t.Run("v6", func(t *testing.T) {
		plugin := &plugins.Plugin{Name: "test-chain-nil-handler6ctx", Setup6Ctx: func(_ ...string) (handler.Handler6Ctx, error) {
			return nil, nil
		}}
		register(t, plugin)

		conf := &config.Config{Server6: &config.ServerConfig{
			Plugins: []config.PluginConfig{{Name: plugin.Name}},
		}}
		chains, err := plugins.LoadChains(conf)
		assert.Nil(t, chains)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no DHCPv6 handler for plugin test-chain-nil-handler6ctx")
	})
}
