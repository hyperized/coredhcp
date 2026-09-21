// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package dns hands clients the recursive resolvers they should use: option
// 6 on DHCPv4, the DNS Recursive Name Server option (23, RFC 3646) on
// DHCPv6. Both families are handled, and each server section configures an
// instance of its own.
//
//	server4:
//	  plugins:
//	    - dns: 8.8.8.8 8.8.4.4
//	server6:
//	  plugins:
//	    - dns: 2001:4860:4860::8888 2001:4860:4860::8844
//
// # Arguments
//
// One or more resolver addresses, in the order clients should try them.
// There is no default. A dns line with nothing after it fails setup, and so
// does an argument that is not an address.
//
// Under server4 every argument has to be an IPv4 address and the error says
// as much for one that is not. Under server6 any address that parses is
// accepted, an IPv4 one included, and that one then goes out as an
// IPv4-mapped address which no client will make anything of. Write the
// resolvers for the family you are configuring.
//
// The list is read once at startup, so changing it means editing the
// configuration and restarting.
//
// # Behaviour
//
// The option is sent only when the client asked for it, and the two families
// read "asked for it" differently. A DHCPv6 request has to name option 23 in
// its Option Request Option; one that sends no ORO gets no resolvers. A
// DHCPv4 request with no parameter request list at all counts as asking for
// everything, which is how dhcpv4.IsOptionRequested reads RFC 2131 section
// 3.5, so that client does get option 6.
//
// A relayed DHCPv6 request is unwrapped first to reach the client's own
// message. One whose relay chain cannot be read is logged and dropped.
//
// The plugin never ends the chain and does not care whether an address has
// been allocated yet.
//
// # Placement
//
// Anywhere ahead of a plugin that ends the chain. dns overwrites a resolver
// list already on the response and is overwritten in turn by a later plugin
// that sets one, so whichever runs last wins. List dns first when a
// scope-aware plugin such as subnet, redis or options should be able to
// override it for the clients it knows about, and last when every client
// should get the same pair whatever else ran.
package dns
