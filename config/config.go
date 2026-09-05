// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package config parses and validates the coredhcp server configuration.
package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cast"
	"github.com/spf13/viper"

	"github.com/coredhcp/coredhcp/logger"
)

var log = logger.GetLogger("config")

type protocolVersion int

const (
	protocolV6 protocolVersion = 6
	protocolV4 protocolVersion = 4
)

// Config holds the DHCPv6/v4 server configuration
type Config struct {
	v       *viper.Viper
	Server6 *ServerConfig
	Server4 *ServerConfig
}

// New returns a new initialized instance of a Config object
func New() *Config {
	return &Config{v: viper.New()}
}

// ServerConfig holds a server configuration that is specific to either the
// DHCPv6 server or the DHCPv4 server.
type ServerConfig struct {
	Addresses []net.UDPAddr
	Plugins   []PluginConfig
}

// PluginConfig holds the configuration of a plugin
type PluginConfig struct {
	Name string
	Args []string
}

// Load reads a configuration file and returns a Config object, or an error if
// any. With no override path, it searches $XDG_CONFIG_HOME/coredhcp/,
// $HOME/.coredhcp/ and /etc/coredhcp/, in that order, before finally trying
// the working directory. The working directory goes last so a config file left
// in whatever directory the server happens to be started from does not quietly
// win over the one an operator installed.
func Load(pathOverride string) (*Config, error) {
	log.Print("Loading configuration")
	c := New()
	c.v.SetConfigType("yml")
	if pathOverride != "" {
		c.v.SetConfigFile(pathOverride)
	} else {
		c.v.SetConfigName("config")
		c.v.AddConfigPath("$XDG_CONFIG_HOME/coredhcp/")
		c.v.AddConfigPath("$HOME/.coredhcp/")
		c.v.AddConfigPath("/etc/coredhcp/")
		c.v.AddConfigPath(".")
	}

	if err := c.v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err := c.parseConfig(protocolV6); err != nil {
		return nil, err
	}
	if err := c.parseConfig(protocolV4); err != nil {
		return nil, err
	}
	if c.Server6 == nil && c.Server4 == nil {
		return nil, ErrorFromString("need at least one valid config for DHCPv6 or DHCPv4")
	}
	return c, nil
}

func protoVersionCheck(v protocolVersion) error {
	if v != protocolV6 && v != protocolV4 {
		return fmt.Errorf("invalid protocol version: %d", v)
	}
	return nil
}

func parsePlugins(pluginList []any) ([]PluginConfig, error) {
	plugins := make([]PluginConfig, 0, len(pluginList))
	for idx, val := range pluginList {
		conf := cast.ToStringMap(val)
		if conf == nil {
			return nil, ErrorFromString("dhcpv6: plugin #%d is not a string map", idx)
		}
		// make sure that only one item is specified, since it's a
		// map name -> args
		if len(conf) != 1 {
			return nil, ErrorFromString("dhcpv6: exactly one plugin per item can be specified")
		}
		var (
			name string
			args []string
		)
		// only one item, as enforced above, so read just that
		for k, v := range conf {
			name = k
			args = strings.Fields(cast.ToString(v))
			break
		}
		plugins = append(plugins, PluginConfig{Name: name, Args: args})
	}
	return plugins, nil
}

func (c *Config) getPlugins(ver protocolVersion) ([]PluginConfig, error) {
	if err := protoVersionCheck(ver); err != nil {
		return nil, err
	}
	pluginList := cast.ToSlice(c.v.Get(fmt.Sprintf("server%d.plugins", ver)))
	if pluginList == nil {
		return nil, ErrorFromString("dhcpv%d: invalid plugins section, not a list or no plugin specified", ver)
	}
	return parsePlugins(pluginList)
}

func (c *Config) parseConfig(ver protocolVersion) error {
	if err := protoVersionCheck(ver); err != nil {
		return err
	}
	if exists := c.v.Get(fmt.Sprintf("server%d", ver)); exists == nil {
		// it is valid to have no server configuration defined
		return nil
	}
	// read plugin configuration
	plugins, err := c.getPlugins(ver)
	if err != nil {
		return err
	}
	for _, p := range plugins {
		log.Printf("DHCPv%d: found plugin `%s` with %d args: %v", ver, p.Name, len(p.Args), RedactArgs(p.Args))
	}

	listeners, err := c.parseListen(ver)
	if err != nil {
		return err
	}

	sc := ServerConfig{
		Addresses: listeners,
		Plugins:   plugins,
	}
	switch ver {
	case protocolV6:
		c.Server6 = &sc
	case protocolV4:
		c.Server4 = &sc
	}
	return nil
}
