// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package serverid decides whether a request is addressed to this server,
// and stamps this server's identity on every reply. It serves both
// families, and the plugin is named server_id in a configuration file
// rather than after its package.
//
//	server4:
//	  plugins:
//	    - server_id: 10.0.0.1
//
//	server6:
//	  plugins:
//	    - server_id: LL aa:bb:cc:dd:ee:ff
//
// Under server4 the only argument is this server's IPv4 address in dotted
// form, and it is required. An empty list, an argument that is not an
// address, or an IPv6 address fails setup with the argument quoted, and the
// server does not start. Only the first argument is read.
//
// Under server6 there are two arguments, a DUID type and a link-layer
// address, and both are required. The type is LL or LLT, case-insensitive,
// also spelled duid-ll, duid_ll, duid-llt and duid_llt. The value is a MAC
// address in any form net.ParseMAC takes. Fewer than two arguments, an
// empty argument, a value that is not a MAC, or a type that is not one of
// those fails setup with the argument quoted. EN and UUID are refused by
// name: they are recognised spellings that are not implemented yet. Only
// the first two arguments are read. The hardware type is always Ethernet,
// and a DUID-LLT is built with a zero timestamp, so the DUID depends on
// nothing but the MAC written in the configuration and survives a restart.
//
// # Placement
//
// server_id belongs first in the chain, or straight after metrics,
// ratelimit and relay, and in any case before any plugin that allocates or
// frees a lease. It ends the chain for every request it turns down, so a
// request for another server never reaches lease state. A request it
// accepts passes on with the identity stamped on the response, which no
// later plugin should overwrite.
//
// # DHCPv4
//
// The field that decides whether a request is for this server is option 54,
// the server identifier. A client in SELECTING state copies it from the
// offer it accepted, and every other server on the segment is supposed to
// stay quiet. A request whose option 54 names some other address is
// dropped. DISCOVER and INFORM normally carry no option 54 at all and pass.
//
// RELEASE and DECLINE are the exception: RFC 2131 Table 5 makes option 54 a
// MUST on both, since both are unicast to the server that owns the lease.
// One arriving without it, or with an option 54 the library cannot parse,
// cannot be shown to be addressed here and is dropped like a mismatch.
// That matters because neither message is authenticated and neither is
// answered, so without the check any host can aim one at any server.
//
// Every response that passes gets the identifier twice: in option 54, and
// in the siaddr header field.
//
// A request whose opcode is not BootRequest is passed on unchanged with a
// warning. The server refuses those before the chain runs, so in a running
// server this only fires when the handler is driven directly.
//
// # DHCPv6
//
// The equivalent field is the ServerID option, holding the DUID built at
// setup, and RFC 8415 section 16 splits the message types in two.
//
//   - Solicit, Confirm and Rebind are dropped if they carry a ServerID at
//     all. A client sends these to every server on the link, so naming one
//     is a contradiction.
//   - Request, Renew, Decline and Release are dropped if they carry no
//     ServerID. These continue an exchange with one specific server.
//
// Anything else that carries a ServerID is dropped when the DUID does not
// match this server's, which is what keeps two servers on one link from
// both answering. A message that passes gets this server's DUID written
// onto the response.
//
// A relayed request is read through its Relay-forward wrapping to reach the
// client's own message. A wrapping the library cannot unpack is a defect in
// the server rather than in the packet, since the same unpacking already
// succeeded before the chain ran, so it is logged as one and the request is
// dropped.
package serverid
