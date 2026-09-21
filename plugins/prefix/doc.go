// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package prefix implements a plugin offering prefixes to clients requesting
// them with IA_PREFIX requests.
//
// The plugin takes the pool and the allocation size, and optionally a lease
// duration and named arguments in any order:
//
//	server6:
//	  plugins:
//	    - prefix: 2001:db8::/48 64 1h sweep:30m max-prefixes:4
//
// The pool is the base prefix that assigned prefixes are carved from, and has
// to be an IPv6 prefix: delegation only exists for DHCPv6. The allocation size
// is the largest prefix handed to a client: one asking for something bigger
// gets a prefix of this size. The lease duration defaults to 1h.
//
//	sweep:<duration>       how often lapsed delegations are reclaimed in the
//	                       background. Defaults to half the lease duration,
//	                       floored at 30s.
//	max-prefixes:<count>   how many delegations one client may hold at a
//	                       time. Defaults to 4.
//
// Delegations used to be handed out and never taken back. The expiry was
// written and pushed out on renewal, but nothing read it and the allocator was
// never asked to free anything, so a pool of 65536 /64s served 70000 clients
// and then served nobody, with the lease map still holding every client that
// had ever asked. Prefixes now go back to the pool from two places: the
// background sweeper, and the request path for the client in front of us.
//
// # What one packet may cost
//
// Nothing in DHCPv6 authenticates a client, so the work and the addresses one
// datagram can claim are all capped.
//
// A message is answered for at most maxIAPDsPerMessage IA_PD options. Every
// IA_PD in a message used to be served: a 146-byte SOLICIT carrying eight of
// them emptied a /62 pool of four /64s, and roughly 4096 fit in a full
// datagram, at which point the reply grew too large to send and the sender
// paid nothing at all.
//
// The same cap applies to the IAPrefix hints inside one IA_PD, since a hint
// matching a lease the client already holds is renewed and answered with a
// prefix.
//
// One client, meaning one DUID, holds at most max-prefixes delegations. An
// IA_PD that would take it past that is answered with NoPrefixAvail rather
// than served, which is the same answer an exhausted pool gives.
//
// A client DUID longer than RFC 8415 §11.1 allows is dropped, since the lease
// map is keyed by the DUID's wire form and would otherwise grow by whatever a
// sender cared to put in the option.
//
// # Placement
//
// The plugin does not end the chain, so a second delegating plugin listed
// behind it still runs and adds its own IA_PD next to this one's.
package prefix
