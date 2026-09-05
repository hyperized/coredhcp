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
//
// A plugin declares at most one setup function per protocol family: Setup4 or
// Setup4Ctx for DHCPv4, Setup6 or Setup6Ctx for DHCPv6. The Ctx forms get a
// context carrying handler.RequestInfo, which is where the interface a
// request arrived on and its source address come from; the plain forms are
// the original signature and stay supported. Declaring both for one family is
// refused by RegisterPlugin, since only one of the two could ever be called.
// All four may be nil: a family with no setup function is one this plugin
// does not handle.
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

// ErrConflictingSetup is what RegisterPlugin reports for a plugin that
// declares both the plain and the context-aware setup function for one
// family. Loading it would have to pick one and quietly ignore the other,
// which is never what the author meant.
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
		// TODO: the package-global registry map is the last piece of shared
		// state here; replace it with a Registry type the caller constructs
		// and injects, alongside the planned functional-options server API.
		log.Panicf("Plugin '%s' is already registered", plugin.Name)
	}
	RegisteredPlugins[plugin.Name] = plugin
	return nil
}

// checkSetupFuncs rejects a plugin that declares both setup forms for the
// same protocol family.
func checkSetupFuncs(p *Plugin) error {
	if p.Setup4 != nil && p.Setup4Ctx != nil {
		return fmt.Errorf("plugin `%s`, DHCPv4: %w", p.Name, ErrConflictingSetup)
	}
	if p.Setup6 != nil && p.Setup6Ctx != nil {
		return fmt.Errorf("plugin `%s`, DHCPv6: %w", p.Name, ErrConflictingSetup)
	}
	return nil
}

// Link4 is one entry of a DHCPv4 handler chain, together with the plugin it
// was loaded from. Plugins with no setup function for the family are skipped
// while loading, so a position in the chain does not line up with the
// configured plugin list: the name has to travel with the handler.
type Link4 struct {
	Name    string
	Args    []string
	Handler handler.Handler4Ctx

	// WantsContext is set for a plugin loaded through Setup4Ctx, whose
	// handler reads the context it is called with. A handler from a plain
	// Setup4 is wrapped in an adapter that ignores it, so the server can
	// leave the context empty when no link in the chain wants one. See
	// WantsContext.
	WantsContext bool
}

// Link6 is Link4's DHCPv6 counterpart.
type Link6 struct {
	Name         string
	Args         []string
	Handler      handler.Handler6Ctx
	WantsContext bool
}

// chainLink is the one thing WantsContext needs of a chain entry. The method
// is unexported, so Link4 and Link6 are the only types that satisfy it.
type chainLink interface {
	wantsContext() bool
}

// wantsContext reports whether this link's plugin reads the context.
func (l Link4) wantsContext() bool { return l.WantsContext }

// wantsContext reports whether this link's plugin reads the context.
func (l Link6) wantsContext() bool { return l.WantsContext }

// WantsContext reports whether any link in chain came from a context-aware
// setup function. The server asks once per listener while starting up and
// then skips building a context per packet when the answer is no, which
// leaves a chain of plain handlers as cheap as it was before contexts
// existed.
func WantsContext[L chainLink](chain []L) bool {
	for i := range chain {
		if chain[i].wantsContext() {
			return true
		}
	}
	return false
}

// Chains holds both families' loaded handler chains in configuration order.
// A family without a server section in the configuration gets a nil chain.
type Chains struct {
	V4 []Link4
	V6 []Link6
}

// loadHandlers walks one protocol family's plugin list, calling each
// configured plugin's setup function in order and turning every handler it
// gets back into a chain link. Plugins without a setup function for this
// family are skipped with a warning, matching the long-standing behaviour.
// setup also reports whether the plugin asked for a context, which travels
// into the link.
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

// setup4Of picks the DHCPv4 setup function to call for a plugin and says
// whether that plugin reads the context. A plain Setup4 comes back wrapped in
// an adapter that drops the context; the error and the nil handler it may
// return pass through unchanged, because loadHandlers has to keep telling
// those two apart. A plugin with neither setup function returns nil.
func setup4Of(p *Plugin) (func(...string) (handler.Handler4Ctx, error), bool) {
	if p.Setup4Ctx != nil {
		return p.Setup4Ctx, true
	}
	if p.Setup4 == nil {
		return nil, false
	}
	return func(args ...string) (handler.Handler4Ctx, error) {
		h, err := p.Setup4(args...)
		if err != nil || h == nil {
			return nil, err
		}
		return func(_ context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			return h(req, resp)
		}, nil
	}, false
}

// setup6Of is setup4Of for DHCPv6.
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

// newLink4 pairs a loaded DHCPv4 handler with the configuration it came from.
// Args are copied because the link outlives the load and callers hold on to
// it for the life of the server.
func newLink4(conf config.PluginConfig, h handler.Handler4Ctx, wantsCtx bool) Link4 {
	return Link4{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h, WantsContext: wantsCtx}
}

// newLink6 is newLink4's DHCPv6 counterpart.
func newLink6(conf config.PluginConfig, h handler.Handler6Ctx, wantsCtx bool) Link6 {
	return Link6{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h, WantsContext: wantsCtx}
}

// LoadChains reads a Config object and loads the plugins as specified in the
// `plugins` section, in order, into one handler chain per protocol family.
// For a plugin to be available, it must have been previously registered with
// plugins.RegisterPlugin. This is normally done at plugin import time.
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

// LoadPlugins loads the configured plugins and returns the bare handler
// chains, dropping the plugin names LoadChains keeps alongside them. Callers
// that have to name the plugin a handler came from want LoadChains instead.
// This function returns the list of loaded v4 plugins, the list of loaded v6
// plugins, and an error if any.
//
// The handlers it returns take no context, so a context-aware plugin loaded
// this way is called with context.Background() and sees no
// handler.RequestInfo: there is no request here to describe one. Callers that
// serve real traffic use LoadChains, which the server does.
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
