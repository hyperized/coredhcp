// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugins

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
)

// poisonedContext panics the instant any of its methods run, so passing one
// to a handler proves the handler never touches its context argument at all,
// rather than merely surviving a nil one.
type poisonedContext struct{}

func (poisonedContext) Deadline() (time.Time, bool) { panic("context was touched") }
func (poisonedContext) Done() <-chan struct{}       { panic("context was touched") }
func (poisonedContext) Err() error                  { panic("context was touched") }
func (poisonedContext) Value(any) any               { panic("context was touched") }

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

	l4 := newLink4(config.PluginConfig{Name: "copy-4", Args: args}, func(_ context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		return resp, false
	}, false)
	l6 := newLink6(config.PluginConfig{Name: "copy-6", Args: args}, func(_ context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		return resp, false
	}, false)
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
	l4 := newLink4(config.PluginConfig{Name: "no-args-4"}, nil, false)
	l6 := newLink6(config.PluginConfig{Name: "no-args-6"}, nil, false)
	assert.Nil(t, l4.Args)
	assert.Nil(t, l6.Args)
}

// newLink4 and newLink6 just store whatever wantsCtx they are handed; this
// pins that down so a future refactor of the loadHandlers plumbing cannot
// silently drop it.
func TestNewLinkCarriesWantsContext(t *testing.T) {
	h4 := func(_ context.Context, _, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }
	h6 := func(_ context.Context, _, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }

	cases := []struct {
		name string
		want bool
	}{
		{name: "context aware", want: true},
		{name: "plain", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l4 := newLink4(config.PluginConfig{Name: "n4"}, h4, tc.want)
			l6 := newLink6(config.PluginConfig{Name: "n6"}, h6, tc.want)
			assert.Equal(t, tc.want, l4.WantsContext)
			assert.Equal(t, tc.want, l6.WantsContext)
		})
	}
}

// funcPointer identifies which underlying function a func value wraps, since
// Go func values cannot be compared with == or assert.Equal. It only
// distinguishes distinct top-level functions and closures, which is exactly
// what these tests need: proof that setup4Of/setup6Of returned the plugin's
// own function rather than a new one.
func funcPointer(f any) uintptr {
	return reflect.ValueOf(f).Pointer()
}

func TestCheckSetupFuncs(t *testing.T) {
	stub4 := func(_ ...string) (handler.Handler4, error) { return nil, nil }
	stub4Ctx := func(_ ...string) (handler.Handler4Ctx, error) { return nil, nil }
	stub6 := func(_ ...string) (handler.Handler6, error) { return nil, nil }
	stub6Ctx := func(_ ...string) (handler.Handler6Ctx, error) { return nil, nil }

	cases := []struct {
		name    string
		plugin  *Plugin
		wantErr string
	}{
		{
			name:   "neither family conflicts",
			plugin: &Plugin{Name: "p-clean", Setup4: stub4, Setup6Ctx: stub6Ctx},
		},
		{
			name:    "v4 declares both forms",
			plugin:  &Plugin{Name: "p-v4", Setup4: stub4, Setup4Ctx: stub4Ctx},
			wantErr: "plugin `p-v4`, DHCPv4: " + ErrConflictingSetup.Error(),
		},
		{
			name:    "v6 declares both forms",
			plugin:  &Plugin{Name: "p-v6", Setup6: stub6, Setup6Ctx: stub6Ctx},
			wantErr: "plugin `p-v6`, DHCPv6: " + ErrConflictingSetup.Error(),
		},
		{
			// Both families conflict at once; the function checks v4 first,
			// so that is the error that comes back.
			name:    "both families conflict",
			plugin:  &Plugin{Name: "p-both", Setup4: stub4, Setup4Ctx: stub4Ctx, Setup6: stub6, Setup6Ctx: stub6Ctx},
			wantErr: "plugin `p-both`, DHCPv4: " + ErrConflictingSetup.Error(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSetupFuncs(tc.plugin)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.EqualError(t, err, tc.wantErr)
			assert.ErrorIs(t, err, ErrConflictingSetup)
		})
	}
}

// TestSetup4OfNeitherForm covers the plugin that does not handle DHCPv4 at
// all: no accessor to call, and it should not be mistaken for a context-aware
// one.
func TestSetup4OfNeitherForm(t *testing.T) {
	got, wantsCtx := setup4Of(&Plugin{Name: "no-v4"})
	assert.Nil(t, got)
	assert.False(t, wantsCtx)
}

// TestSetup4OfContextForm checks that a plugin declaring Setup4Ctx gets that
// exact function back, unwrapped, with wantsCtx true.
func TestSetup4OfContextForm(t *testing.T) {
	stub := func(_ ...string) (handler.Handler4Ctx, error) { return nil, nil }
	p := &Plugin{Name: "ctx-v4", Setup4Ctx: stub}

	got, wantsCtx := setup4Of(p)
	require.NotNil(t, got)
	assert.True(t, wantsCtx)
	assert.Equal(t, funcPointer(stub), funcPointer(got))
}

// TestSetup4OfPlainFormAdapts exercises the three behaviours the adapter
// around a plain Setup4 has to get right: an error from the wrapped setup
// function must reach the caller unchanged, a (nil, nil) result must map to a
// nil handler rather than a handler that panics on first use, and a real
// handler must reach the caller with the context stripped away.
func TestSetup4OfPlainFormAdapts(t *testing.T) {
	t.Run("setup error passes through unchanged", func(t *testing.T) {
		wantErr := errors.New("setup4 boom")
		p := &Plugin{Name: "plain-v4-error", Setup4: func(_ ...string) (handler.Handler4, error) {
			return nil, wantErr
		}}

		setupFn, wantsCtx := setup4Of(p)
		require.NotNil(t, setupFn)
		assert.False(t, wantsCtx)

		h, err := setupFn("a", "b")
		assert.Nil(t, h)
		assert.Same(t, wantErr, err)
	})

	t.Run("nil handler maps to nil handler", func(t *testing.T) {
		p := &Plugin{Name: "plain-v4-nil", Setup4: func(_ ...string) (handler.Handler4, error) {
			return nil, nil
		}}

		setupFn, _ := setup4Of(p)
		h, err := setupFn()
		assert.NoError(t, err)
		assert.Nil(t, h)
	})

	t.Run("handler forwards to the original and ignores the context", func(t *testing.T) {
		var gotArgs []string
		p := &Plugin{Name: "plain-v4-forward", Setup4: func(args ...string) (handler.Handler4, error) {
			gotArgs = args
			return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				return resp, true
			}, nil
		}}

		setupFn, _ := setup4Of(p)
		h, err := setupFn("x", "y")
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Equal(t, []string{"x", "y"}, gotArgs)

		want := &dhcpv4.DHCPv4{}
		resp, stop := h(poisonedContext{}, nil, want)
		assert.Same(t, want, resp)
		assert.True(t, stop)
	})
}

// TestSetup6OfNeitherForm is TestSetup4OfNeitherForm's DHCPv6 counterpart.
func TestSetup6OfNeitherForm(t *testing.T) {
	got, wantsCtx := setup6Of(&Plugin{Name: "no-v6"})
	assert.Nil(t, got)
	assert.False(t, wantsCtx)
}

// TestSetup6OfContextForm is TestSetup4OfContextForm's DHCPv6 counterpart.
func TestSetup6OfContextForm(t *testing.T) {
	stub := func(_ ...string) (handler.Handler6Ctx, error) { return nil, nil }
	p := &Plugin{Name: "ctx-v6", Setup6Ctx: stub}

	got, wantsCtx := setup6Of(p)
	require.NotNil(t, got)
	assert.True(t, wantsCtx)
	assert.Equal(t, funcPointer(stub), funcPointer(got))
}

// TestSetup6OfPlainFormAdapts is TestSetup4OfPlainFormAdapts's DHCPv6
// counterpart.
func TestSetup6OfPlainFormAdapts(t *testing.T) {
	t.Run("setup error passes through unchanged", func(t *testing.T) {
		wantErr := errors.New("setup6 boom")
		p := &Plugin{Name: "plain-v6-error", Setup6: func(_ ...string) (handler.Handler6, error) {
			return nil, wantErr
		}}

		setupFn, wantsCtx := setup6Of(p)
		require.NotNil(t, setupFn)
		assert.False(t, wantsCtx)

		h, err := setupFn("a", "b")
		assert.Nil(t, h)
		assert.Same(t, wantErr, err)
	})

	t.Run("nil handler maps to nil handler", func(t *testing.T) {
		p := &Plugin{Name: "plain-v6-nil", Setup6: func(_ ...string) (handler.Handler6, error) {
			return nil, nil
		}}

		setupFn, _ := setup6Of(p)
		h, err := setupFn()
		assert.NoError(t, err)
		assert.Nil(t, h)
	})

	t.Run("handler forwards to the original and ignores the context", func(t *testing.T) {
		var gotArgs []string
		p := &Plugin{Name: "plain-v6-forward", Setup6: func(args ...string) (handler.Handler6, error) {
			gotArgs = args
			return func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
				return resp, true
			}, nil
		}}

		setupFn, _ := setup6Of(p)
		h, err := setupFn("x", "y")
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Equal(t, []string{"x", "y"}, gotArgs)

		want := &dhcpv6.Message{}
		resp, stop := h(poisonedContext{}, nil, want)
		assert.Same(t, want, resp)
		assert.True(t, stop)
	})
}
