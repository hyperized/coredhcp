// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package plugins provides the plugin registry and the setup machinery that
// wires configured plugins into the server's handler chains.
package plugins

import (
	"errors"

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
		// TODO this highlights that asking the plugins to register themselves
		// is not the right approach. Need to register them in the main program.
		log.Panicf("Plugin '%s' is already registered", plugin.Name)
	}
	RegisteredPlugins[plugin.Name] = plugin
	return nil
}

// loadHandlers walks one protocol family's plugin list, calling each
// configured plugin's setup function in order. Plugins without a setup
// function for this family are skipped with a warning, matching the
// long-standing behaviour.
func loadHandlers[H any](family string, list []config.PluginConfig,
	setup func(*Plugin) func(...string) (H, error), isNil func(H) bool,
) ([]H, error) {
	handlers := make([]H, 0, len(list))
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
		handlers = append(handlers, h)
	}
	return handlers, nil
}

// LoadPlugins reads a Config object and loads the plugins as specified in the
// `plugins` section, in order. For a plugin to be available, it must have been
// previously registered with plugins.RegisterPlugin. This is normally done at
// plugin import time.
// This function returns the list of loaded v4 plugins, the list of loaded v6
// plugins, and an error if any.
func LoadPlugins(conf *config.Config) ([]handler.Handler4, []handler.Handler6, error) {
	log.Print("Loading plugins...")

	if conf.Server6 == nil && conf.Server4 == nil {
		return nil, nil, errors.New("no configuration found for either DHCPv6 or DHCPv4")
	}

	handlers4 := make([]handler.Handler4, 0)
	handlers6 := make([]handler.Handler6, 0)
	var err error
	if conf.Server6 != nil {
		handlers6, err = loadHandlers("DHCPv6", conf.Server6.Plugins,
			func(p *Plugin) func(...string) (handler.Handler6, error) { return p.Setup6 },
			func(h handler.Handler6) bool { return h == nil },
		)
		if err != nil {
			return nil, nil, err
		}
	}
	if conf.Server4 != nil {
		handlers4, err = loadHandlers("DHCPv4", conf.Server4.Plugins,
			func(p *Plugin) func(...string) (handler.Handler4, error) { return p.Setup4 },
			func(h handler.Handler4) bool { return h == nil },
		)
		if err != nil {
			return nil, nil, err
		}
	}
	return handlers4, handlers6, nil
}
