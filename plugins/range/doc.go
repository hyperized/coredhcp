// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package rangeplugin implements a plugin that hands out DHCPv4 leases
// from an address range, persisting them in a sqlite database.
//
// Configure it with the lease database, the first and last address of the
// pool, and the lease time:
//
//	server4:
//	  plugins:
//	    - range: leases.sqlite3 10.0.0.100 10.0.0.200 1h
//
// Four optional arguments may follow, in any order:
//
//	sweep:<duration>              how often expired leases are reclaimed in
//	                              the background. Defaults to half the lease
//	                              time, floored at 30s.
//	decline-probation:<duration>  how long an address a client declined is
//	                              held back from the pool. Defaults to 24h,
//	                              the same as Kea. 0 hands a declined address
//	                              straight back out.
//	decline-max:<count>           how many declined addresses may be held
//	                              back at the same time. Defaults to a tenth
//	                              of the pool, held between 1 and 65536.
//	                              0 disables the quarantine, the same as
//	                              decline-probation:0 does.
//	max-leases:<count>            how many leases this instance may hold at
//	                              once. Defaults to 65536. A pool with room
//	                              for more addresses than that needs this
//	                              raised, or it stops handing out leases at
//	                              the bound. 0 turns the bound off.
//
// Leases are reclaimed in two places: a background sweeper on a ticker, and
// lazily on the allocation path when the pool looks exhausted. Without either,
// expired leases pile up in the map, the allocator and the database forever,
// and a stable population of churning clients eventually exhausts the pool
// permanently (upstream issues #148 and #182).
//
// # RELEASE and DECLINE
//
// A DHCPRELEASE frees a lease only when the sender holds one and names it in
// ciaddr, which is how RFC 2131 §4.4.6 has a client identify the lease it is
// giving up. The message is never acknowledged and its chaddr is trivially
// forged, so a server that goes by the MAC alone can have its pool emptied by
// anyone on the segment: twenty forged releases drained an eleven-address
// pool, and a release from a MAC with no lease used to allocate one.
//
// A DHCPDECLINE means the client found the address already in use on the link.
// The lease goes away, but the address stays out of the pool for the probation
// period so the next client does not walk into the same conflict. Probation is
// tracked in memory only: a restart puts every declined address back into
// circulation.
//
// The quarantine is bounded, because a decline is as unauthenticated as a
// release. Nothing stops one host on the segment taking an offer and declining
// it, two packets per address, until the whole pool sits in probation and
// nobody gets a lease for the next day. At most decline-max addresses are held
// back at a time: past that, a declined address goes straight back to the
// pool, and a pool that runs dry ends the probation of whichever address has
// been held longest. Probation says which addresses look risky, it never
// reserves one.
//
// # Storage
//
// The reply to a client waits until its lease has reached the lease
// database, and a lease that cannot be written is refused rather than handed
// out: an address nobody can see after a restart is how two clients end up
// with the same one. Writes are queued to one writer goroutine, so a slow
// disk costs queue depth rather than blocking every other client, the
// sweeper and the lease API behind one insert.
//
// # Placement
//
// The plugin does not end the chain, so a range or subnet listed after it
// overwrites the address this one handed out: one pool plugin per chain.
package rangeplugin
