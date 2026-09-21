// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package ipv6only tells a DHCPv4 client that this network would rather it
// used IPv6, and how long to hold off before asking for an IPv4 address
// again (option 108, RFC 8925). DHCPv4 only: the option exists to turn IPv4
// off, so it has no DHCPv6 counterpart.
//
//	server4:
//	  plugins:
//	    - ipv6only: 1800s
//
// # Argument
//
// One optional argument, V6ONLY_WAIT: how long the client should wait,
// written as a Go duration such as 1800s or 30m. It defaults to 0s, which is
// not the same as no wait at all. RFC 8925 section 3.2 has a client raise
// anything below MIN_V6ONLY_WAIT to MIN_V6ONLY_WAIT, which section 3.4 sets
// at 300 seconds, so the default asks for the shortest wait a client will
// honour. The same table gives V6ONLY_WAIT itself a default of 1800
// seconds, which is the value to write out when you want the RFC's own.
//
// A value ParseDuration cannot read fails setup, and so does a second
// argument. Both errors say what was expected instead.
//
// # Behaviour
//
// A request naming option 108 in its parameter request list gets the option
// and ends the chain there. Nothing listed after ipv6only runs for that
// client, which is the point: the OFFER leaves with yiaddr 0.0.0.0 (RFC 8925
// section 3.3) and no address is taken out of the pool. A request that does
// not name the option passes on untouched.
//
// A RELEASE and a DECLINE also pass through untouched, and the plugin checks
// the message type for that reason alone. Neither carries a parameter
// request list, and dhcpv4.IsOptionRequested reads an absent list as every
// option being requested, so without the check a release would look like a
// client asking about option 108. The chain would end at ipv6only, the
// allocator behind it would never see the release, and the lease would stand
// until it expired. The server sends nothing for either message type anyway
// (RFC 2131 section 4.4); the chain runs for them only so that plugins can
// free or quarantine the lease.
//
// # Placement
//
// After server_id, before every allocator.
//
// Before the allocators is what saves the address: ipv6only ends the chain,
// so range, file and the rest never run for a client that takes the option.
// After server_id is the same argument the other way round. The OFFER still
// has to carry a server identifier, which RFC 2131 table 3 makes a MUST on
// every OFFER and ACK, and a plugin listed behind ipv6only does not get the
// chance to add one.
package ipv6only
