// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package plugins provides the plugin registry and the setup machinery that
// wires configured plugins into the server's handler chains.
package plugins

import (
	"errors"
	"slices"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
)

var log = logger.GetLogger("plugins")

// Plugin represents a plugin object.
// Setup6 and Setup4 are the setup functions for DHCPv6 and DHCPv4 handlers
// respectively. Both setup functions can be nil.
type Plugin struct {
	Name   string
	Setup6 SetupFunc6
	Setup4 SetupFunc4
}

// RegisteredPlugins maps a plugin name to a Plugin instance.
var RegisteredPlugins = make(map[string]*Plugin)

// SetupFunc6 defines a plugin setup function for DHCPv6
type SetupFunc6 func(args ...string) (handler.Handler6, error)

// SetupFunc4 defines a plugin setup function for DHCPv6
type SetupFunc4 func(args ...string) (handler.Handler4, error)

// RegisterPlugin registers a plugin.
func RegisterPlugin(plugin *Plugin) error {
	if plugin == nil {
		return errors.New("cannot register nil plugin")
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

// Link4 is one entry of a DHCPv4 handler chain, together with the plugin it
// was loaded from. Plugins with no setup function for the family are skipped
// while loading, so a position in the chain does not line up with the
// configured plugin list: the name has to travel with the handler.
type Link4 struct {
	Name    string
	Args    []string
	Handler handler.Handler4
}

// Link6 is Link4's DHCPv6 counterpart.
type Link6 struct {
	Name    string
	Args    []string
	Handler handler.Handler6
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
func loadHandlers[H, L any](family string, list []config.PluginConfig,
	setup func(*Plugin) func(...string) (H, error), isNil func(H) bool,
	link func(config.PluginConfig, H) L,
) ([]L, error) {
	links := make([]L, 0, len(list))
	for _, pluginConf := range list {
		plugin, ok := RegisteredPlugins[pluginConf.Name]
		if !ok {
			return nil, config.ErrorFromString("%s: unknown plugin `%s`", family, pluginConf.Name)
		}
		log.Printf("%s: loading plugin `%s`", family, pluginConf.Name)
		setupFn := setup(plugin)
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
		links = append(links, link(pluginConf, h))
	}
	return links, nil
}

// newLink4 pairs a loaded DHCPv4 handler with the configuration it came from.
// Args are copied because the link outlives the load and callers hold on to
// it for the life of the server.
func newLink4(conf config.PluginConfig, h handler.Handler4) Link4 {
	return Link4{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h}
}

// newLink6 is newLink4's DHCPv6 counterpart.
func newLink6(conf config.PluginConfig, h handler.Handler6) Link6 {
	return Link6{Name: conf.Name, Args: slices.Clone(conf.Args), Handler: h}
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
		chains.V6, err = loadHandlers("DHCPv6", conf.Server6.Plugins,
			func(p *Plugin) func(...string) (handler.Handler6, error) { return p.Setup6 },
			func(h handler.Handler6) bool { return h == nil },
			newLink6,
		)
		if err != nil {
			return nil, err
		}
	}
	if conf.Server4 != nil {
		chains.V4, err = loadHandlers("DHCPv4", conf.Server4.Plugins,
			func(p *Plugin) func(...string) (handler.Handler4, error) { return p.Setup4 },
			func(h handler.Handler4) bool { return h == nil },
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
func LoadPlugins(conf *config.Config) ([]handler.Handler4, []handler.Handler6, error) {
	chains, err := LoadChains(conf)
	if err != nil {
		return nil, nil, err
	}
	handlers4 := make([]handler.Handler4, 0, len(chains.V4))
	for _, l := range chains.V4 {
		handlers4 = append(handlers4, l.Handler)
	}
	handlers6 := make([]handler.Handler6, 0, len(chains.V6))
	for _, l := range chains.V6 {
		handlers6 = append(handlers6, l.Handler)
	}
	return handlers4, handlers6, nil
}
