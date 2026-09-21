// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ntp tells clients which NTP servers to use. It serves both
// families, and each one is configured on its own: a dual-stack server
// lists the plugin twice, once under server4 and once under server6, since
// the two configurations share nothing.
//
//	server4:
//	  plugins:
//	    - ntp: 192.0.2.123 192.0.2.124
//
//	server6:
//	  plugins:
//	    - ntp: 2001:db8::123
//
// Every argument is one NTP server address and at least one is required;
// there is no default. Under server4 each address is IPv4 in dotted form,
// under server6 each is IPv6 in colon-hex form. An empty list, an argument
// that does not parse, or an address of the other family fails setup with
// the argument quoted, and the server does not start. Addresses reach the
// client in the order they are written, which RFC 2132 section 8.3 calls
// order of preference.
//
// # What is served
//
// DHCPv4 clients get option 42, a list of IPv4 addresses. DHCPv6 clients get
// option 56 from RFC 5908, holding one srvaddr suboption per address. The
// DHCPv6 option can also carry a multicast address or an FQDN; this plugin
// writes server addresses only.
//
// # Placement
//
// This is an option plugin. It never ends the chain and it never drops a
// request, so it belongs with the other option plugins: after server_id and
// any filtering plugin, and before the plugin that hands out an address,
// because the first allocator to answer a client ends the chain. A plugin
// listed after this one that writes option 42 or option 56 wins, since each
// handler overwrites what the one before it left on the response.
//
// # Behaviour
//
// The option goes on every response the chain builds. That includes the
// ACK for a DHCPINFORM, which is the exchange a client uses to ask for
// options without taking a lease, and the response built for a DHCPv4
// RELEASE or DECLINE, which the server throws away without sending.
package ntp
