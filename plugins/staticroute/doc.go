// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package staticroute serves classless static routes to DHCPv4 clients, as
// option 121 (RFC 3442). It is the option to use for anything beyond the
// default gateway: a route to a subnet that sits behind a second router on
// the same link, for example.
//
//	server4:
//	  plugins:
//	    - staticroute: 10.99.0.0/16,192.0.2.1 172.16.0.0/12,192.0.2.2
//
// Every argument is one route, written as <destination>/<prefix
// length>,<gateway> with a comma and no space in between, since the
// configuration loader splits arguments on whitespace. At least one route
// is required and there is no default. An argument that is not exactly one
// comma-separated pair, a destination net.ParseCIDR rejects, or a gateway
// that is not an address fails setup with the offending piece quoted, and
// the server does not start.
//
// Both halves have to be IPv4. Option 121 has four-byte fields and no room
// for anything else, so an IPv6 destination or gateway is refused at setup
// as well.
//
// # DHCPv4 only
//
// There is no DHCPv6 half. DHCPv6 has no equivalent option: routing is a
// neighbour discovery matter there, with the default gateway in the router
// advertisement and anything more specific in an RFC 4191 route
// information option. Listing staticroute under server6 is not a startup
// error, but the loader warns that the plugin has no setup function for
// that family and skips it.
//
// # Option 121, option 33 and option 3
//
// RFC 3442 replaces the older static route option 33, which could only
// express classful routes, and has a client that understands 121 ignore 33
// when both are present. This plugin serves 121 only, so a client old
// enough to want 33 falls back on the default gateway from the router
// plugin.
//
// The same section has a client that received option 121 ignore option 3,
// the default gateway, as well. Configure a default route of your own here
// when you serve this option, or clients that honour RFC 3442 end up with
// routes to the listed subnets and nowhere else.
//
// # Placement
//
// This is an option plugin. It never ends the chain and it never drops a
// request, so it belongs with the other option plugins: after server_id and
// any filtering plugin, and before the plugin that hands out an address,
// because the first allocator to answer a client ends the chain. A plugin
// listed after this one that writes option 121 wins, since each handler
// overwrites what the one before it left on the response.
//
// # Behaviour
//
// The option goes on every response the chain builds. That includes the
// ACK for a DHCPINFORM, which is the exchange a client uses to ask for
// options without taking a lease, and the response built for a RELEASE or
// DECLINE, which the server throws away without sending.
//
// All routes go in one option, in the order they are configured, and the
// option can grow past the 255 bytes a single DHCP option holds. A long
// list is then split over several instances of option 121 by the encoder,
// which RFC 3396 has clients concatenate again.
package staticroute
