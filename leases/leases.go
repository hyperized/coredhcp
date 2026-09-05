// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leases is the contract between the plugins that hold leases and
// whatever wants to read them: an API plugin, a terminal UI, an exporter.
//
// The server has never had a way to answer "who holds what right now"
// (coredhcp/coredhcp#111). Every plugin that hands out addresses keeps its own
// map behind its own lock, in whatever shape suits its protocol: the range
// plugin keys IPv4 leases by MAC, the prefix plugin keys delegations by DUID,
// the file plugin holds static reservations. A reader cannot reach into any of
// those without taking a lock it does not own.
//
// This package is the narrow waist between the two sides. A plugin implements
// Source over its own state and registers the instance during setup; a
// consumer asks the registry for the sources and calls them. Nothing here
// imports a plugin, so a plugin can depend on this package without a cycle,
// and nothing here holds lease state of its own: the plugins remain the only
// owners of that.
//
// The JSON tags on Lease and Pool are part of the contract too. They are the
// shape the leaseapi plugin serves and a remote UI decodes, and keeping them
// on the types keeps that shape in one place instead of in a parallel set of
// structs that has to be kept in step.
package leases

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Lease is one address or prefix a client holds right now.
//
// A Lease is a snapshot taken under the source's lock, not a view of live
// state: nothing in it changes after Source.Leases returns, and the client may
// well have released the address by the time it is read.
type Lease struct {
	// Family is 4 for a DHCPv4 lease and 6 for a DHCPv6 one.
	Family uint8 `json:"family"`

	// Client identifies the holder: the hardware address for DHCPv4
	// ("00:11:22:33:44:55"), the DUID in lower-case hex for DHCPv6. A DUID
	// is opaque bytes with no canonical text form, so hex is what a reader
	// can match against the wire and against another source's output.
	Client string `json:"client"`

	// IAID is the identity association the lease belongs to, and is 0 when
	// the source does not track one. DHCPv4 has no IAID at all, and the
	// prefix plugin keys its delegations by DUID alone.
	IAID uint32 `json:"iaid,omitempty"`

	// Address is what the client holds, always as a prefix: a /32 for a
	// DHCPv4 address, a /128 for a DHCPv6 address, and the delegated length
	// for a prefix delegation. One field covers all three, so a reader does
	// not have to switch on the family to know what it is looking at.
	Address netip.Prefix `json:"address"`

	// Hostname is what the client called itself, empty when it said nothing
	// or the source does not keep it.
	Hostname string `json:"hostname,omitempty"`

	// Expires is when the lease lapses. It is the zero time for a static
	// reservation, which never expires, and omitted from the JSON in that
	// case rather than serialised as year one.
	Expires time.Time `json:"expires,omitzero"`

	// Static reports a reservation that was configured rather than
	// allocated. A static lease is not held against a pool and cannot be
	// released.
	Static bool `json:"static"`

	// Source names the plugin instance this lease came from, matching
	// Source.Name. Two range plugins in one config are two sources, so the
	// name carries the first argument as well as the plugin name.
	Source string `json:"source"`
}

// Pool is how much address space one source manages and how much of it is
// spoken for.
type Pool struct {
	// Source names the plugin instance, matching Source.Name.
	Source string `json:"source"`

	// Family is 4 for an IPv4 pool and 6 for an IPv6 one.
	Family uint8 `json:"family"`

	// Range is the pool as the operator configured it: "10.0.0.100-10.0.0.200"
	// for an address range, "2001:db8::/48" for a prefix pool.
	Range string `json:"range"`

	// Size is how many addresses or blocks the pool holds, Used how many are
	// currently leased out, and Quarantined how many are held back from
	// allocation without being leased, which today means addresses a client
	// declined. Used and Quarantined are disjoint and both count against
	// Size.
	//
	// Size is capped at the largest int rather than wrapped: a pool covering
	// the whole IPv4 space, or a /48 delegating /128s, counts more blocks
	// than an int holds on a 32-bit build.
	Size        int `json:"size"`
	Used        int `json:"used"`
	Quarantined int `json:"quarantined"`
}

// Source is one plugin instance that holds leases.
//
// Implementations copy their state under their own lock and return fresh
// slices, so a caller may hold on to what it gets and read it at leisure
// without blocking the packet path. Both methods may be called concurrently
// with each other and with the plugin serving traffic.
//
// Leases returns nil for a source that holds none, and Pools returns nil for a
// source with no pool of its own: the file plugin serves reservations an
// operator wrote down, not addresses it manages.
type Source interface {
	// Name identifies this instance as "<plugin> <first argument>", for
	// example "range leases.sqlite3". Names are not unique: two range
	// plugins on the same lease file would report the same name.
	Name() string

	// Leases returns every lease the source holds right now.
	Leases() []Lease

	// Pools returns the pools the source allocates from.
	Pools() []Pool
}

// registry holds the registered sources.
//
// Package-level state is what the plugin interface leaves room for: a setup
// function gets its arguments and returns a handler, with nowhere to hand an
// instance to a consumer that is itself only a plugin. Registration order is
// kept, which is configuration order, and the mutex is held only around the
// slice: calling into a Source happens after Sources has returned, so a slow
// reader never blocks a plugin's setup.
var registry struct {
	mu      sync.Mutex
	sources []Source
}

// Register adds s to the registry. Plugins call it from their setup function
// once the instance is built and safe to read.
//
// Sources are not deduplicated. Two instances of the same plugin are two
// sources even when they report the same name, because they hold different
// leases. Registering nil does nothing, so a plugin that guards its own setup
// badly cannot leave a nil in the registry for every reader to trip over.
func Register(s Source) {
	if s == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.sources = append(registry.sources, s)
}

// Sources returns the registered sources in registration order.
//
// The slice is a copy, so the caller may keep it, iterate it slowly, and
// register or unregister while doing so. The Source values in it are the
// registered instances themselves, which is the point: reading one is what
// gets the current leases.
func Sources() []Source {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return slices.Clone(registry.sources)
}

// Unregister removes the first registration of s, and does nothing if s was
// never registered.
//
// Nothing in the server unregisters: plugin setup runs once at startup and the
// instances live as long as the process. This exists for tests, which build a
// plugin per case and would otherwise leave every one of them visible to the
// next test.
//
// Sources are compared by identity, so s has to be the value that was passed
// to Register. Every implementation registers a pointer, which is comparable;
// an implementation whose dynamic type is not comparable panics here, the same
// way it would in an == between two interface values.
func Unregister(s Source) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if i := slices.Index(registry.sources, s); i >= 0 {
		registry.sources = slices.Delete(registry.sources, i, i+1)
	}
}
