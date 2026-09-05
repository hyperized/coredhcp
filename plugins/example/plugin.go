// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package example implements a documented no-op plugin that serves as a
// starting point for writing new plugins.
package example

import (
	"context"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

// A plugin takes a logger tagged with its own prefix.
var log = logger.GetLogger("plugins/example")

// Plugin is the registry entry a plugin package exports, under a name unique
// across the binary. A nil setup function means the plugin skips that family.
// Importing the package is not enough: the name has to be listed in the
// server's `plugins` section in config.yml before anything runs.
var Plugin = plugins.Plugin{
	Name:   "example",
	Setup6: setup6,
	Setup4: setup4,
}

// PluginContext is a second plugin from the same package: the registry keys on
// the name, not the package. It declares Setup4Ctx where Plugin declares the
// plain Setup4, and a plugin picks one form or the other per family.
var PluginContext = plugins.Plugin{
	Name:      "example_context",
	Setup4Ctx: setup4Ctx,
}

// Setup runs once at load. The handler it returns is called per packet, but
// only while no earlier plugin in the chain has stopped it.
func setup6(_ ...string) (handler.Handler6, error) {
	log.Printf("loaded plugin for DHCPv6.")
	return exampleHandler6, nil
}

func setup4(_ ...string) (handler.Handler4, error) {
	log.Printf("loaded plugin for DHCPv4.")
	return exampleHandler4, nil
}

// setup4Ctx is the context-aware form, the one PluginContext declares.
func setup4Ctx(_ ...string) (handler.Handler4Ctx, error) {
	log.Printf("loaded context-aware plugin for DHCPv4.")
	return exampleHandler4Ctx, nil
}

// A handler is given the request and the response built so far. Returning true
// stops the chain, and a nil response drops the request instead of answering.
func exampleHandler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	log.Printf("received DHCPv6 packet: %s", req.Summary())
	return resp, false
}

func exampleHandler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	log.Printf("received DHCPv4 packet: %s", req.Summary())
	return resp, false
}

// Neither the arrival interface nor the source address is anywhere in the DHCP
// payload, so a plugin keying on either reads them from the context. They can
// be absent, which is why the ok form is not optional.
func exampleHandler4Ctx(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		log.Printf("received DHCPv4 packet: %s", req.Summary())
		return resp, false
	}
	log.Printf("received DHCPv4 packet on %s from %s: %s", info.Interface, info.Peer, req.Summary())
	return resp, false
}
