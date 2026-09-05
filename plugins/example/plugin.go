// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package example implements a documented no-op plugin that serves as a
// starting point for writing new plugins.
package example

// This is an example plugin that inspects a packet and prints it out. The code
// is commented in a way that should walk you through the implementation of your
// own plugins.
// Feedback is welcome!

import (
	"context"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

// We use a customizable logger, as part of the `logger` package. You can use
// `logger.GetLogger()` to get a logger carrying this plugin's prefix, with
// the usual leveled printf-style methods plus `With` for structured context.
// More information in the docstring of the logger package.
var log = logger.GetLogger("plugins/example")

// Plugin wraps the information necessary to register a plugin.
// In the main package, you need to export a `plugins.Plugin` object called
// `Plugin`, so it can be registered into the plugin registry.
// Just import your plugin, and fill the structure with plugin name and setup
// functions:
//
// import (
//
//	"github.com/coredhcp/coredhcp/plugins"
//	"github.com/coredhcp/coredhcp/plugins/example"
//
// )
//
//	var Plugin = plugins.Plugin{
//	    Name: "example",
//	    Setup6: setup6,
//	    Setup4: setup4,
//	}
//
// Name is simply the name used to register the plugin. It must be unique to
// other registered plugins, or the operation will fail. In other words, don't
// declare plugins with colliding names.
//
// Setup6 and Setup4 are the setup functions for DHCPv6 and DHCPv4 traffic
// handlers. They conform to the `plugins.SetupFunc6` and `plugins.SetupFunc4`
// interfaces, so they must return a `plugins.Handler6` and a `plugins.Handler4`
// respectively.
// A `nil` setup function means that that protocol won't be handled by this
// plugin.
//
// Note that importing the plugin is not enough to use it: you have to
// explicitly specify the intention to use it in the `config.yml` file, in the
// plugins section. For example:
//
// server6:
//
//	listen: '[::]547'
//	- example:
//	- server_id: LL aa:bb:cc:dd:ee:ff
//	- file: "leases.txt"
var Plugin = plugins.Plugin{
	Name:   "example",
	Setup6: setup6,
	Setup4: setup4,
}

// PluginContext is a second plugin declared from this same package: nothing
// ties a plugin to a package one to one, only its name to a slot in the
// registry, which is why this one carries a name of its own. It reaches a
// running server the way Plugin does, by being listed in the binary's plugin
// set.
//
// Where Plugin declares the plain Setup4, this one declares Setup4Ctx and its
// handler is given the context the server dispatched the request with. A
// plugin picks one form or the other per family; RegisterPlugin refuses one
// that declares both, since only one of them could ever be called. Neither
// Setup6 nor Setup6Ctx is set here, which is how a plugin says it does not
// handle that family.
var PluginContext = plugins.Plugin{
	Name:      "example_context",
	Setup4Ctx: setup4Ctx,
}

// setup6 is the setup function to initialize the handler for DHCPv6
// traffic. This function implements the `plugin.SetupFunc6` interface.
// This function returns a `handler.Handler6` function, and an error if any.
// In this example we do very little in the setup function, and just return the
// `exampleHandler6` function. Such function will be called for every DHCPv6
// packet that the server receives. Remember that a handler may not be called
// for each packet, if the handler chain is interrupted before reaching it.
func setup6(_ ...string) (handler.Handler6, error) {
	log.Printf("loaded plugin for DHCPv6.")
	return exampleHandler6, nil
}

// setup4 behaves like setupExample6, but for DHCPv4 packets. It
// implements the `plugin.SetupFunc4` interface.
func setup4(_ ...string) (handler.Handler4, error) {
	log.Printf("loaded plugin for DHCPv4.")
	return exampleHandler4, nil
}

// setup4Ctx is setup4's context-aware counterpart, returned by PluginContext
// for DHCPv4. It implements the `plugins.SetupFunc4Ctx` interface, and hands
// back `exampleHandler4Ctx` instead of `exampleHandler4`.
func setup4Ctx(_ ...string) (handler.Handler4Ctx, error) {
	log.Printf("loaded context-aware plugin for DHCPv4.")
	return exampleHandler4Ctx, nil
}

// exampleHandler6 handles DHCPv6 packets for the example plugin. It implements
// the `handler.Handler6` interface. The input arguments are the request packet
// that the server received from a client, and the response packet that has been
// computed so far. This function returns the response packet to be sent back to
// the client, and a boolean.
// The response can be either the same response packet received as input, a
// modified response packet, or nil. If nil, the server will not reply to the
// client, basically dropping the request.
// The returned boolean indicates to the server whether the chain of plugins
// should continue or not. If `true`, the server will stop at this plugin, and
// respond to the client (or drop the response, if nil). If `false`, the server
// will call the next plugin in the chan, using the returned response packet as
// input for the next plugin.
func exampleHandler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	log.Printf("received DHCPv6 packet: %s", req.Summary())
	// return the unmodified response, and false. This means that the next
	// plugin in the chain will be called, and the unmodified response packet
	// will be used as its input.
	return resp, false
}

// exampleHandler4 behaves like exampleHandler6, but for DHCPv4 packets. It
// implements the `handler.Handler4` interface.
func exampleHandler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	log.Printf("received DHCPv4 packet: %s", req.Summary())
	// return the unmodified response, and false. This means that the next
	// plugin in the chain will be called, and the unmodified response packet
	// will be used as its input.
	return resp, false
}

// exampleHandler4Ctx behaves like exampleHandler4, but implements the
// `handler.Handler4Ctx` interface, so it also gets the context the server
// dispatched the request with. That context is where handler.RequestInfo
// lives: which interface the request arrived on and where it came from,
// neither of which is anywhere in the DHCP payload itself. This is what a
// plugin choosing a subnet per interface, or rate limiting by source address,
// would key on.
//
// The information can be absent, as it is for a handler called through the
// legacy plugins.LoadPlugins API or straight from a test, so a handler reads
// it with the ok form and copes with false rather than assuming it is always
// there. And ctx belongs to the call: nothing pulled out of it may be kept
// around after the handler returns.
func exampleHandler4Ctx(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		// No request information: the handler was called outside the
		// server's dispatch path, so there is nothing to describe.
		log.Printf("received DHCPv4 packet: %s", req.Summary())
		return resp, false
	}
	log.Printf("received DHCPv4 packet on %s from %s: %s", info.Interface, info.Peer, req.Summary())
	return resp, false
}
