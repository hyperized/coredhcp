// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package redis implements a plugin that reads per-client DHCP settings from
// a Redis server, so leases can be handed out from a database that other
// systems write to while coredhcp is running.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - redis: 10.0.0.9:6379 password:env:REDIS_PASSWORD timeout:2s prefix:mac: lifetime:1h key:mac
//
// The first argument is the server address. It is either a plain host:port,
// or a URL: redis://[user[:password]@]host[:port][/db] for a cleartext
// connection and rediss://... for TLS. A URL without a port uses 6379, and
// the path selects the database number. TLS verifies the server against the
// system trust store using the host from the URL; there is no switch to turn
// that off.
//
// The remaining arguments are optional and may appear in any order. An
// argument that is not one of these fails setup by name:
//
//   - password:<value> or password:env:<NAME> overrides any password in the
//     URL. The env: form reads the variable once, during setup, and fails if
//     it is unset or empty. Passwords are never logged, and neither is the
//     userinfo part of the URL.
//   - timeout:<duration> bounds the dial, the TLS handshake and every
//     command. It defaults to 2s and has to be positive.
//   - prefix:<key-prefix> is put in front of the client identifier to build
//     the key. It defaults to the key mode's own prefix, and an explicit one
//     wins wherever it appears on the line. An empty prefix means the key is
//     the bare identifier.
//   - lifetime:<duration> is the DHCPv6 preferred and valid lifetime used for
//     clients whose hash carries no leaseTime. It defaults to 1h.
//   - key:<mac|duid|client-id> selects the client identifier the keys are
//     built from. It defaults to mac.
//
// # Data model
//
// One hash per client, keyed by <prefix><identifier>. Which identifier that
// is, and how it is written, follows the key: argument.
//
// key:mac is the default and works for both families. The MAC is written the
// way net.HardwareAddr.String() writes it, lowercase hex, colon separated,
// and the prefix defaults to "mac:".
//
//	HSET mac:aa:bb:cc:dd:ee:ff ipv4 10.0.0.5/24 router 10.0.0.1 dns 10.0.0.2,10.0.0.3 leaseTime 12h
//
// key:duid is for server6 and fails setup under server4. A MAC is a poor key
// there: a client identifying with a DUID-EN or a DUID-UUID carries no
// link-layer address in its DUID, and behind a relay that sends no client
// link-layer address option there is nothing to extract either. The key is
// the DUID as it goes on the wire, two-octet type code included, in
// lowercase hex with no separators, behind the default prefix "duid:".
//
//	HSET duid:00030001aabbccddeeff ipv6 2001:db8::10:1 leaseTime 12h
//
// A DUID is at most 130 octets, since RFC 8415 section 11.1 caps it at 128
// and the type code is two more. A request carrying a longer one is passed
// to the next plugin rather than looked up.
//
// key:client-id is for server4 and fails setup under server6. The key is the
// raw bytes of option 61 in lowercase hex, behind the default prefix
// "client-id:". RFC 2132 section 9.14 puts a type octet first: type 1 is a
// hardware address, so a client whose identifier is its MAC appears as 01
// followed by the six address bytes, and an RFC 4361 client puts a DUID
// behind type 255. A client that sends no option 61 at all is passed to the
// next plugin.
//
//	HSET client-id:01aabbccddeeff ipv4 10.0.0.5/24
//
// The fields this plugin reads:
//
//   - ipv4: the address handed to a DHCPv4 client, bare (10.0.0.5) or in CIDR
//     notation (10.0.0.5/24). The CIDR form also sets the subnet mask option.
//   - ipv6: the address handed to a DHCPv6 client, bare or in CIDR notation.
//     A prefix length is accepted and ignored, because an IA_NA carries an
//     address and no mask.
//   - router: the IPv4 default gateway, option 3.
//   - dns: resolver addresses, comma separated. Both families may be listed
//     in the same field; the DHCPv4 handler uses the IPv4 entries and the
//     DHCPv6 handler the IPv6 ones. Like the dedicated dns plugin, the option
//     is only added when the client asked for it. For DHCPv4 that includes a
//     client that sent no parameter request list at all, which RFC 2131
//     section 3.5 reads as asking for everything available.
//   - leaseTime: a Go duration such as 12h or 3600s. It becomes the DHCPv4
//     lease time option and the DHCPv6 address lifetimes.
//
// Any other field is ignored, with a line in the debug log naming it.
//
// # Behaviour
//
// Setup sends one PING. A failure there is logged as a warning naming the
// address and the error, so a wrong password or a typo in the address shows
// up at startup, but it does not fail setup: a DHCP server that refuses to
// start because a database is briefly down is worse than one that starts and
// serves its other plugins while the database comes back.
//
// At request time the two failure modes are deliberately different. A client
// that Redis does not know, or knows without an address for this family, is
// passed on so a later plugin such as range can serve it. A lookup that fails
// because Redis is unreachable, refuses the credentials, or answers something
// unparseable drops the request instead: a client with a documented static
// address must not silently fall through to a dynamic pool because the
// backend hiccuped, and a dropped DHCP request is retried moments later.
//
// A DHCPv4 RELEASE or DECLINE, and their DHCPv6 equivalents, skip the lookup
// entirely and are passed straight to the next plugin: coredhcp never sends a
// reply to either message, and this plugin keeps no lease state that one
// could act on, so looking one up would only spend a Redis round trip that an
// unauthenticated sender on the segment can trigger at will with a new MAC
// address each time.
//
// # Placement
//
// For DHCPv4 the plugin answers the request, so list it after the plugins
// whose options should still apply and before any dynamic pool.
package redis
