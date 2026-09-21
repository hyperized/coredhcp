// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leasetime sets how long a DHCPv4 client may keep the address it
// was given (option 51). The plugin is registered as lease_time, which is
// the name the configuration uses. DHCPv6 is not handled: its lifetimes
// travel inside the IA options, and whichever plugin hands out the address
// sets them there.
//
//	server4:
//	  plugins:
//	    - lease_time: 3600s
//
// # Argument
//
// One duration, required, in Go's format: 3600s, 1h, 90m. There is no
// default, so a lease_time line with nothing after it fails setup, and so
// does a value ParseDuration cannot read. Only the first argument is looked
// at; anything after it is ignored rather than rejected.
//
// # Behaviour
//
// The lease time is written only when the response does not carry one
// already. A plugin that knows a lease time for this particular client
// keeps it, and lease_time is the fallback for everyone else.
//
// Two requests pass through untouched. An INFORM asks for options while the
// client already has an address from somewhere else, and RFC 2131 section
// 4.3.5 says the server must not send it a lease expiration time. Anything
// whose opcode is not BootRequest is not a client request at all. A RELEASE
// and a DECLINE do get an option 51, on a response the server then discards
// without sending, so it never reaches the wire.
//
// The plugin does not end the chain.
//
// # Placement
//
// Anywhere. Order against the allocators turns out not to matter: range and
// redis overwrite option 51 with the lease time of their pool or their hash
// when they run after lease_time, and lease_time leaves their value alone
// when it runs after them, so the more specific value wins either way.
// Listing it near the top with the other defaults is as good a place as any.
package leasetime
