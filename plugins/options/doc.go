// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package options implements a plugin that sets arbitrary DHCP options on
// responses, for the many options that do not warrant a plugin of their own.
//
// Every argument is one option specification of the form `code:type:value`,
// and the plugin is repeatable:
//
//	server4:
//	  plugins:
//	    - options: 15:string:home.lan 42:ip:192.0.2.10
//
// The specification is split on the first two colons only, so a value may
// itself contain colons, as IPv6 addresses and URLs do.
//
// The type names an encoder from a fixed allow-list (string, ip, iplist,
// uint8, uint16, uint32, hex, bool); everything is validated at setup time so
// a typo in the configuration fails the server at startup instead of emitting
// a malformed packet later. Codes must fit the protocol: 1-255 for DHCPv4,
// 1-65535 for DHCPv6. Code 0 is the DHCPv4 pad option and is rejected in both
// families.
//
// Options are set unconditionally, exactly like the dns and router plugins do,
// and deliberately not conditioned on the client's parameter request list:
// a client cannot ask for an option it has never heard of, so honouring the
// request list would make this plugin useless for the vendor and site-local
// options it exists to serve.
//
// No option code is blocked. Setting a code the server manages elsewhere
// (51 lease time, 54 server identifier, 1 subnet mask, 3 router) is the
// operator's own foot to shoot, and plugin order decides the winner: handlers
// run in configuration order and each one overwrites what came before, so an
// `options` entry placed after the `lease_time` plugin overrides it, and one
// placed before it does not. DHCPv4 code 255 is the end marker and setting it
// will corrupt the packet.
package options
