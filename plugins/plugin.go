// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package plugins provides the plugin registry and the setup machinery that
// wires configured plugins into the server's handler chains.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
)

var log = logger.GetLogger("plugins")

// Plugin represents a plugin object.
// At most one setup function per family: declaring both forms for one family
// is refused, since only one of the two could ever be called.
type Plugin struct {
	Name      string
	Setup6    SetupFunc6
	Setup4    SetupFunc4
	Setup6Ctx SetupFunc6Ctx
	Setup4Ctx SetupFunc4Ctx
}

// RegisteredPlugins maps a plugin name to a Plugin instance.
var RegisteredPlugins = make(map[string]*Plugin)

// SetupFunc6 defines a plugin setup function for DHCPv6
type SetupFunc6 func(args ...string) (handler.Handler6, error)

// SetupFunc4 defines a plugin setup function for DHCPv4
type SetupFunc4 func(args ...string) (handler.Handler4, error)

// SetupFunc6Ctx defines a context-aware plugin setup function for DHCPv6.
type SetupFunc6Ctx func(args ...string) (handler.Handler6Ctx, error)

// SetupFunc4Ctx defines a context-aware plugin setup function for DHCPv4.
type SetupFunc4Ctx func(args ...string) (handler.Handler4Ctx, error)

// ErrConflictingSetup reports a plugin declaring both setup forms for one family.
var ErrConflictingSetup = errors.New("plugin declares both a plain and a context-aware setup function for the same protocol family")

// RegisterPlugin registers a plugin.
func RegisterPlugin(plugin *Plugin) error {
	if plugin == nil {
		return errors.New("cannot register nil plugin")
	}
	if err := checkSetupFuncs(plugin); err != nil {
		return err
	}
	log.Printf("Registering plugin '%s'", plugin.Name)
	if _, ok := RegisteredPlugins[plugin.Name]; ok {
		// TODO: replace the package-global registry with an injected Registry type.
		log.Panicf("Plugin '%s' is already registered", plugin.Name)
	}
	RegisteredPlugins[plugin.Name] = plugin
	return nil
}

func checkSetupFuncs(p *Plugin) error {
	if p.Setup4 != nil && p.Setup4Ctx != nil {
		return fmt.Errorf("plugin `%s`, DHCPv4: %w", p.Name, ErrConflictingSetup)
	}
	if p.Setup6 != nil && p.Setup6Ctx != nil {
		return fmt.Errorf("plugin `%s`, DHCPv6: %w", p.Name, ErrConflictingSetup)
	}
	return nil
}

// Link4 is one entry of a DHCPv4 handler chain.
// Skipped plugins leave chain positions out of step with the configured list,
// so the name has to travel with the handler.
type Link4 struct {
	Name    string
	Args    []string
	Handler handler.Handler4Ctx

	// False for a plain Setup4, whose handler is wrapped in an adapter that
	// drops the context.
	WantsContext bool
}

// Link6 is Link4's DHCPv6 counterpart.
type Link6 struct {
	Name         string
	Args         []string
	Handler      handler.Handler6Ctx
	WantsContext bool
}

type chainLink interface {
	wantsContext() bool
}

func (l Link4) wantsContext() bool { return l.WantsContext }

func (l Link6) wantsContext() bool { return l.WantsContext }

// WantsContext reports whether any link in chain reads the context.
// The server asks once per listener, then skips building one per packet.
func WantsContext[L chainLink](chain []L) bool {
	for i := range chain {
		if chain[i].wantsContext() {
			return true
		}
	}
	return false
}

// Chains holds both families' loaded handler chains in configuration order.
// A family with no server section in the configuration gets a nil chain.
type Chains struct {
	V4 []Link4
	V6 []Link6
}

func loadHandlers[H, L any](family string, list []config.PluginConfig,
	setup func(*Plugin) (func(...string) (H, error), bool), isNil func(H) bool,
	link func(config.PluginConfig, H, bool) L,
) ([]L, error) {
	links := make([]L, 0, len(list))
	for _, pluginConf := range list {
		plugin, ok := RegisteredPlugins[pluginConf.Name]
		if !ok {
			return nil, config.ErrorFromString("%s: unknown plugin `%s`", family, pluginConf.Name)
		}
		log.Printf("%s: loading plugin `%s`", family, pluginConf.Name)
		setupFn, wantsCtx := setup(plugin)
		if setupFn == nil {
			// Not an error: a plugin commonly serves only one family.
			log.Warningf("%s: plugin `%s` has no setup function for %s", family, pluginConf.Name, family)
			continue
		}
		h, err := setupFn(pluginConf.Args...)
		if err != nil {
			return nil, err
		}
		if isNil(h) {
			return nil, config.ErrorFromString("no %s handler for plugin %s", family, pluginConf.Name)
		}
		links = append(links, link(pluginConf, h, wantsCtx))
	}
	return links, nil
}

func setup4Of(p *Plugin) (func(...string) (handler.Handler4Ctx, error), bool) {
	if p.Setup4Ctx != nil {
		return p.Setup4Ctx, true
	}
	if p.Setup4 == nil {
		return nil, false
	}
	return func(args ...string) (handler.Handler4Ctx, error) {
		h, err := p.Setup4(args...)
		// A nil handler passes through as nil, not as an error: loadHandlers
		// reports a different failure for each.
		if err != nil || h == nil {
			return nil, err
		}
		return func(_ context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			return h(req, resp)
		}, nil
	}, false
}

func setup6Of(p *Plugin) (func(...string) (handler.Handler6Ctx, error), bool) {
	if p.Setup6Ctx != nil {
		return p.Setup6Ctx, true
	}
	if p.Setup6 == nil {
		return nil, false
	}
	return func(args ...string) (handler.Handler6Ctx, error) {
		h, err := p.Setup6(args...)
		if err != nil || h == nil {
			return nil, err
		}
		return func(_ context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			return h(req, resp)
		}, nil
	}, false
}

// Args are cloned: the link is held for the life of the server.
func newLink4(conf config.PluginConfig, h handler.Handler4Ctx, wantsCtx bool) Link4 {
	return Link4{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h, WantsContext: wantsCtx}
}

func newLink6(conf config.PluginConfig, h handler.Handler6Ctx, wantsCtx bool) Link6 {
	return Link6{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h, WantsContext: wantsCtx}
}

// LoadChains loads the configured plugins into one handler chain per family.
// A plugin must already have been registered, normally at import time.
func LoadChains(conf *config.Config) (*Chains, error) {
	log.Print("Loading plugins...")

	if conf.Server6 == nil && conf.Server4 == nil {
		return nil, errors.New("no configuration found for either DHCPv6 or DHCPv4")
	}

	var chains Chains
	var err error
	if conf.Server6 != nil {
		chains.V6, err = loadHandlers("DHCPv6", conf.Server6.Plugins, setup6Of,
			func(h handler.Handler6Ctx) bool { return h == nil },
			newLink6,
		)
		if err != nil {
			return nil, err
		}
	}
	if conf.Server4 != nil {
		chains.V4, err = loadHandlers("DHCPv4", conf.Server4.Plugins, setup4Of,
			func(h handler.Handler4Ctx) bool { return h == nil },
			newLink4,
		)
		if err != nil {
			return nil, err
		}
	}
	return &chains, nil
}

// LoadPlugins is LoadChains without the plugin names, kept for compatibility.
// Its handlers carry no RequestInfo; anything serving real traffic uses LoadChains.
func LoadPlugins(conf *config.Config) ([]handler.Handler4, []handler.Handler6, error) {
	chains, err := LoadChains(conf)
	if err != nil {
		return nil, nil, err
	}
	handlers4 := make([]handler.Handler4, 0, len(chains.V4))
	for _, l := range chains.V4 {
		h := l.Handler
		handlers4 = append(handlers4, func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			return h(context.Background(), req, resp)
		})
	}
	handlers6 := make([]handler.Handler6, 0, len(chains.V6))
	for _, l := range chains.V6 {
		h := l.Handler
		handlers6 = append(handlers6, func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			return h(context.Background(), req, resp)
		})
	}
	return handlers4, handlers6, nil
}
