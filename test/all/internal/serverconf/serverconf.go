// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package serverconf reads the plugin chain out of a rendered coredhcp
// configuration file.
//
// It exists so an end-to-end test can take its expectations from the file the
// server was actually started with, instead of from a second copy of the same
// addresses in the test. A configuration change the clients do not see then
// shows up as a failing assertion rather than as a test that quietly stopped
// checking anything.
//
// This is not a second implementation of the config package: it reads only
// the `- <name>: <args>` items of the two plugin lists, and splits the
// arguments on whitespace exactly the way the server does.
package serverconf

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Plugin is one entry of a plugin chain: the name it was listed under and the
// arguments the server split out of the rest of the line.
type Plugin struct {
	Name string
	Args []string
}

// Chain is the plugin list of one server section, in configuration order.
// Order matters to the server, so it is kept here too.
type Chain []Plugin

// Config is the two chains a coredhcp configuration can hold. A section that
// is absent from the file comes back as a nil Chain.
type Config struct {
	Server4 Chain
	Server6 Chain
}

// section is the part of a server4 or server6 block this package reads.
//
// Plugin arguments are decoded as any rather than as string because YAML
// gives `mtu: 1400` an integer and `netmask: 255.255.255.0` a string, and the
// server itself passes both through a stringifier before splitting them.
type section struct {
	Plugins []map[string]any `yaml:"plugins"`
}

type file struct {
	Server4 *section `yaml:"server4"`
	Server6 *section `yaml:"server6"`
}

// Load reads and parses the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the server configuration at %s: %w; check that the config volume is mounted and config-render ran", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse reads a configuration out of YAML.
func Parse(data []byte) (*Config, error) {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing the server configuration: %w; the file is not the YAML coredhcp writes, check config-render", err)
	}
	cfg := &Config{}
	var err error
	if cfg.Server4, err = f.Server4.chain(4); err != nil {
		return nil, err
	}
	if cfg.Server6, err = f.Server6.chain(6); err != nil {
		return nil, err
	}
	return cfg, nil
}

// chain turns the decoded plugin list into a Chain. A nil section is a
// configuration with no such family, which is not an error.
func (s *section) chain(family int) (Chain, error) {
	if s == nil {
		return nil, nil
	}
	out := make(Chain, 0, len(s.Plugins))
	for i, entry := range s.Plugins {
		if len(entry) != 1 {
			return nil, fmt.Errorf("server%d plugin #%d holds %d names, each item is one `- <name>: <args>` pair", family, i+1, len(entry))
		}
		for name, raw := range entry {
			out = append(out, Plugin{Name: name, Args: strings.Fields(stringify(raw))})
		}
	}
	return out, nil
}

// stringify renders a scalar the way the server's own loader does. A nil
// value is an argument-less plugin, which is a legal line.
func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// Has reports whether the chain lists a plugin under this name.
func (c Chain) Has(name string) bool {
	_, ok := c.First(name)
	return ok
}

// First returns the arguments of the first plugin listed under name.
//
// First rather than only: the leasehook plugin is listed twice in the test's
// own configuration, and a caller asking about it has to say which one it
// means by looking at the arguments it got back.
func (c Chain) First(name string) ([]string, bool) {
	for _, p := range c {
		if p.Name == name {
			return p.Args, true
		}
	}
	return nil, false
}

// All returns the arguments of every plugin listed under name, in order.
func (c Chain) All(name string) [][]string {
	var out [][]string
	for _, p := range c {
		if p.Name == name {
			out = append(out, p.Args)
		}
	}
	return out
}

// Arg returns argument i of the first plugin listed under name.
func (c Chain) Arg(name string, i int) (string, bool) {
	args, ok := c.First(name)
	if !ok || i >= len(args) {
		return "", false
	}
	return args[i], true
}

// MustArg is Arg with the miss turned into an error, for a caller building a
// list of expectations where a missing one is a broken test rather than a
// case to handle.
func (c Chain) MustArg(name string, i int) (string, error) {
	v, ok := c.Arg(name, i)
	if !ok {
		return "", fmt.Errorf("the configuration has no argument #%d for plugin %q; the test expects that plugin to be configured", i, name)
	}
	return v, nil
}

// Named returns the value of the first `<key>:<value>` argument of plugin
// name whose key is key. Several plugins take their optional settings that
// way, and the order they appear in is deliberately not fixed.
func (c Chain) Named(name, key string) (string, bool) {
	args, ok := c.First(name)
	if !ok {
		return "", false
	}
	prefix := key + ":"
	for _, a := range args {
		if v, found := strings.CutPrefix(a, prefix); found {
			return v, true
		}
	}
	return "", false
}

// Index returns the position of the first plugin listed under name, or -1.
// The chain order is part of what a test asserts: an option plugin behind an
// allocator would never run.
func (c Chain) Index(name string) int {
	for i, p := range c {
		if p.Name == name {
			return i
		}
	}
	return -1
}

// Names lists every plugin name in configuration order, repeats included.
func (c Chain) Names() []string {
	out := make([]string, len(c))
	for i, p := range c {
		out[i] = p.Name
	}
	return out
}
