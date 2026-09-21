// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ddns keeps DNS in step with the leases this server hands out.
//
// Every lease it sees becomes an RFC 2136 dynamic update, signed with a TSIG
// key (RFC 8945) and sent to a name server that has been configured to accept
// that key for the zone. Kea has had this for years and dnsmasq still has
// nothing like it, which is why coredhcp was asked for it in upstream issue
// #92 back in 2020.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - ddns: server:10.0.0.53 zone:home.lan key:ddns-key:env:TSIG_KEY algo:hmac-sha256 ttl:300 reverse:10.0.0.0/24 protect:gateway,ns timeout:2s queue:1000
//
// Arguments are key:value pairs in any order. Each may be given once, except
// reverse: and protect:, which may be repeated.
//
// Three are required:
//
//   - server:<address> is the name server to send updates to, as an IP
//     address with an optional port that defaults to 53. It has to be a
//     literal address, not a name: a DHCP server that looks up its DNS
//     server's name through the resolver it is feeding has a bootstrap
//     problem the first time the two disagree.
//   - zone:<name> is the forward zone. A client that sends a bare host name
//     gets it appended to this zone; one that sends a fully qualified name
//     has to send a name under this zone or nothing is written.
//   - key:<name>:<secret> is the TSIG key, where <name> is the key name the
//     server knows it by and <secret> is base64. The env:<NAME> form reads
//     the base64 from an environment variable instead, which is how a secret
//     stays out of the configuration file. The variable is read once, during
//     setup. Key material is never logged, and neither is a secret that
//     failed to decode.
//
// The rest are optional:
//
//   - algo:<name> is one of hmac-sha256 (the default), hmac-sha1 or
//     hmac-sha512, and has to match what the name server has for the key.
//   - ttl:<seconds> is the TTL of the records written, 300 by default.
//   - reverse:<cidr> turns on PTR updates for addresses inside that network.
//     The prefix length has to end on a label boundary of its .arpa tree:
//     a multiple of 8 for IPv4, a multiple of 4 for IPv6. Anything else has
//     no reverse zone of its own, and this plugin will not guess at an RFC
//     2317 delegation.
//   - timeout:<duration> bounds one exchange with the name server. It
//     defaults to 2s.
//   - queue:<n> is how many updates may be waiting at once, 1000 by default.
//   - remove-on-release:on|off decides whether a DHCPRELEASE withdraws the
//     records again. It defaults to on.
//   - protect:<name>[,<name>...] names hosts this plugin will never write,
//     in either direction. A bare label is taken as a name under the zone; a
//     fully qualified one has to sit under it. Use it for names that have to
//     keep meaning what they mean, such as gateway, vpn or ns.
//
// # Behaviour
//
// A DHCPv4 ACK with an address and a usable host name, or a DHCPv6 Reply with
// addresses and an FQDN option, becomes one message: delete every A (or AAAA)
// record at the name, add the lease, and add the DHCID that says whose name
// it now is. They travel in a single update section, which RFC 2136 applies
// as one transaction, so a client that moves to a new address never has two
// records at once. When the address falls inside a reverse: network, a
// second message replaces the PTR in that zone. A DHCPRELEASE takes the
// records away again.
//
// The name a client asks for is the FQDN option -- 81 for DHCPv4, 39 for
// DHCPv6 -- and falls back to option 12 for DHCPv4. Both FQDN options have a
// flag with which a client says it wants no update at all, and that is
// honoured. A name only reaches the zone after it has been lowercased and
// checked: labels of 1 to 63 characters from [a-z0-9-], no leading or
// trailing hyphen, nothing over 253 octets, and the whole name under the
// configured zone. Every packet field here is written by whoever is on the
// segment, so a name that does not pass is dropped with a line in the debug
// log rather than being cleaned up and written anyway.
//
// # Who holds a name
//
// Every name this plugin writes carries a DHCID record (RFC 4701) that
// identifies the client it was written for, and every update is sent under
// the prerequisites of RFC 4703 section 5.3, so a laptop calling itself vpn
// is refused by the name server instead of taking vpn.<zone> from whatever
// was there.
//
// A name that carries no DHCID is held by nobody, and the first client to
// ask for it gets it. That covers records an operator wrote by hand and
// records this plugin itself wrote before it started sending DHCIDs, which
// is worth knowing when upgrading. protect: is how a name is kept out of
// reach of that.
//
// A DHCID is not a secret either: it is a digest of a hardware address or a
// DUID, both of which travel in the clear, so anyone watching the segment
// can put another client's identity in a packet. What this rules out is a
// client taking a name under its own identity; a forged one is a link-layer
// problem, for port security or DHCP snooping.
//
// # Releases
//
// A DHCPRELEASE is not authenticated and is never answered. This instance
// keeps a register in memory of the names it wrote, for which client and at
// which addresses, and a release that does not match it is dropped on the
// packet path with nothing sent. What gets past that is sent as a delete
// under the prerequisite that the DHCID at the name is still the releasing
// client's.
//
// The register does not survive a restart, and it is bounded, so it forgets
// the oldest names once it is full. A release naming a name it has forgotten
// is ignored until the client renews, which leaves a record standing for at
// most one lease time. That is the deliberate direction to fail in: a record
// that lingers costs less than a name anyone can delete by asking.
//
// # Placement
//
// List the plugin after whatever assigns the address, since it reads the
// address out of the response being built. It never answers a request and
// never stops the chain, so nothing after it is affected by where it sits.
//
// The server sends nothing back for a DHCPRELEASE, but it does run the chain
// for one, which is how the withdrawal gets seen.
//
// # Delivery
//
// Updates never happen on the packet path. Each handler drops a job into a
// bounded queue that one worker goroutine drains; when the queue is full the
// job is dropped, counted, and complained about at most once a minute. A DNS
// server that has gone slow must not slow down the DHCP server in front of
// it: a lease handed out a second late is worse than a record that is a
// minute stale.
//
// Listing the plugin under both server4 and server6 builds two instances,
// each with its own queue and worker. They are independent, as two entries in
// the configuration should be.
//
// # Transport
//
// Updates go over UDP and nothing else. The messages are a few hundred octets
// and the answers smaller still, so the truncation the TCP fallback exists
// for does not arise; if a server does set the TC bit anyway, the update is
// logged and counted rather than retried over TCP. One retry covers a lost
// datagram, and past that the client's next renewal will queue the update
// again.
//
// A response is only believed once its TSIG verifies against the MAC of the
// request. The response code is read after that, never before: a spoofed
// REFUSED that is taken at face value turns into a record that silently never
// appears.
//
// One consequence is worth knowing about. A name server asked about a zone it
// does not hold has no key to sign the refusal with, so it answers NOTAUTH
// unsigned; Knot and BIND both do. That reaches the log as an unsigned
// response naming the code it claimed, rather than as a plain NOTAUTH, which
// is the honest reading: the answer may equally have come from anyone on the
// path. Either way the fix is at the name server.
package ddns
