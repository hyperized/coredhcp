// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package sleep implements a plugin that delays responses by a fixed
// duration, useful for testing timeout behaviour.
package sleep

import (
	"fmt"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var (
	pluginName = "sleep"
	log        = logger.GetLogger("plugins/" + pluginName)
)

// Example configuration of the `sleep` plugin, the argument being anything
// time.ParseDuration accepts:
//
// server4:
//   plugins:
//     - sleep 300ms
//     - file: "leases4.txt"

// Plugin contains the `sleep` plugin data.
var Plugin = plugins.Plugin{
	Name:   pluginName,
	Setup6: setup6,
	Setup4: setup4,
}

func setup6(args ...string) (handler.Handler6, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("want exactly one argument, got %d", len(args))
	}
	delay, err := time.ParseDuration(args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %w", err)
	}
	log.Printf("loaded plugin for DHCPv6.")
	return makeSleepHandler6(delay), nil
}

func setup4(args ...string) (handler.Handler4, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("want exactly one argument, got %d", len(args))
	}
	delay, err := time.ParseDuration(args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %w", err)
	}
	log.Printf("loaded plugin for DHCPv4.")
	return makeSleepHandler4(delay), nil
}

func makeSleepHandler6(delay time.Duration) handler.Handler6 {
	return func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		log.Printf("introducing delay of %s in response", delay)
		time.Sleep(delay)
		return resp, false
	}
}

func makeSleepHandler4(delay time.Duration) handler.Handler4 {
	return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		log.Printf("introducing delay of %s in response", delay)
		time.Sleep(delay)
		return resp, false
	}
}
