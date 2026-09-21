// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package relay decides which relayed DHCP requests this server answers, and
// checks that a client releasing a lease speaks from the address it is
// releasing. Both checks work from what the network layer says about a
// datagram, not from what the packet claims about itself.
//
//	server4/server6:
//	  plugins:
//	    - relay: allow 10.0.1.1 10.0.2.0/24 fe80::/10 strict-giaddr release-check:on
//
// The first argument is the keyword allow, followed by one or more addresses
// or CIDR prefixes. Both families may be listed on one line: the DHCPv4
// handler consults the IPv4 entries and the DHCPv6 handler the IPv6 ones, so
// a single configuration serves a dual-stack server. An empty allow list, a
// malformed entry or an option given twice fails setup, and the error names
// the argument that caused it.
//
// The remaining arguments are options, in any order and at most once each:
//
//   - strict-giaddr: on DHCPv4, additionally require the datagram's source
//     address to equal giaddr. Off by default, because RFC 1542 section 4.1
//     lets a multi-homed relay forward from an interface other than the one
//     whose address it put in giaddr, and that mismatch is legitimate. Turn
//     it on when the relays are known to be single-homed.
//   - release-check:on|off: whether to drop a DHCPRELEASE whose ciaddr does
//     not match the datagram's source. On by default.
//
// # What this fixes
//
// On DHCPv4 the server sends its reply to giaddr, at the source port of the
// request, whenever giaddr is set. Both are picked by whoever sent the
// packet, so with no check any host on the segment can make the server send
// an OFFER to any routable address, and the OFFER is larger than the
// DISCOVER that triggered it. The allow list settles that by naming the
// relays that are actually deployed. Everything else is dropped before a
// lease is touched.
//
// The other half is DHCPRELEASE. A release carries the client's chaddr and
// ciaddr and nothing that ties either to the sender, so a host that knows a
// neighbour's address and MAC can free the neighbour's lease. RFC 2131
// section 4.4.6 has the client unicast the release from the address it is
// giving up, so comparing ciaddr against the datagram's source costs nothing
// and rules out the forgery from off-link and from any other address
// on-link. DHCPDECLINE gets no such check, because it carries no ciaddr to
// compare against.
//
// # Without this plugin
//
// A family whose chain does not hold this plugin drops relayed requests in
// the server core instead: a non-zero giaddr on DHCPv4, a Relay-forward on
// DHCPv6. The server says so once at startup and counts the drops. That is
// a safe default rather than a substitute for the allow list, since it
// serves on-link clients and no relay at all. Configuring this plugin
// switches the core check off again and hands the decision to the list
// below.
//
// # DHCPv6
//
// A DHCPv6 relay puts no address in the client's packet the way giaddr does.
// It wraps the message in a Relay-forward and the server replies to the
// datagram's source, so the allow list is matched against that source.
// Relays usually forward from a link-local address, which is why
// fe80::/10 is a sensible entry: it admits any on-link relay while still
// refusing anything routed in from elsewhere.
//
// Two shape checks come with it. A relay chain nested deeper than eight
// layers is dropped, and so is an outermost Relay-forward that carries no
// link address and a hop count above the RFC 8415 HOP_COUNT_LIMIT of 32
// (section 7.6, applied by relays themselves in section 19.1.1). Neither
// occurs in a working deployment, and both are cheap ways to hand the server
// a packet that costs more to process than it did to send.
//
// # Failing closed
//
// The checks need handler.RequestInfo, which the server attaches to the
// request context. A relayed request that arrives without it is dropped in
// both families: the handler is then running outside the server's dispatch
// path, where none of what it is asked to guarantee holds, and the safe
// answer to a request it cannot attribute is no answer. The release
// check is the exception. It is an extra on top of an otherwise ordinary
// on-link request, so a release with no request information passes instead of
// being dropped.
//
// # What this is not
//
// This filters on where packets come from. It is not authentication. A host
// sharing a segment with a trusted relay can still source packets from the
// relay's address if nothing on the switch stops it, and the DHCPv6 check
// trusts an unauthenticated source address in the same way. What it does buy
// is that neither attack above is free any more: both now need a foothold in
// a specific place. Port security, DHCP snooping and IP source guard are what
// hold that ground.
//
// # Placement
//
// relay belongs first in the chain, or straight after a rate limiter, and in
// any case before server_id and before any plugin that allocates or frees a
// lease. The point of it is that a rejected packet never reaches lease state.
//
// # Logging
//
// Drops are logged at Info with the reason and the addresses involved, at
// most one line per second per reason, so a flood of rejected packets does
// not become a flood of log lines. The reasons are a fixed set of constants,
// so the limiter's bookkeeping is bounded by that set and cannot grow with
// traffic.
package relay
