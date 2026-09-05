// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leases is the contract between the plugins that hold leases and
// whatever wants to read them: an API plugin, a terminal UI, an exporter
// (coredhcp/coredhcp#111).
//
// A plugin implements Source over its own state and registers the instance
// during setup. Nothing here imports a plugin, so a plugin can depend on this
// package without a cycle, and no lease state lives here.
//
// The JSON tags on Lease and Pool are part of the contract: they are the shape
// the leaseapi plugin serves and a remote UI decodes.
package leases

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Lease is one address or prefix a client holds right now.
// It is a snapshot taken under the source's lock, not a view of live state.
type Lease struct {
	// Family is 4 for a DHCPv4 lease and 6 for a DHCPv6 one.
	Family uint8 `json:"family"`

	// Client is the hardware address for DHCPv4, the DUID in lower-case hex for
	// DHCPv6, which has no canonical text form of its own.
	Client string `json:"client"`

	// IAID is 0 when the source tracks none; DHCPv4 has no IAID at all.
	IAID uint32 `json:"iaid,omitempty"`

	// Address is always a prefix: /32 for DHCPv4, /128 for a DHCPv6 address,
	// the delegated length for a prefix delegation.
	Address netip.Prefix `json:"address"`

	// Hostname is empty when the client sent none or the source drops it.
	Hostname string `json:"hostname,omitempty"`

	// Expires is the zero time for a static reservation, which never lapses,
	// and is then omitted rather than serialised as year one.
	Expires time.Time `json:"expires,omitzero"`

	// Static reports a configured reservation: not held against a pool, and
	// not releasable.
	Static bool `json:"static"`

	// Source names the plugin instance, matching Source.Name.
	Source string `json:"source"`
}

// Pool is how much address space one source manages and how much is taken.
type Pool struct {
	// Source names the plugin instance, matching Source.Name.
	Source string `json:"source"`

	// Family is 4 for an IPv4 pool and 6 for an IPv6 one.
	Family uint8 `json:"family"`

	// Range is as configured: "10.0.0.100-10.0.0.200" or "2001:db8::/48".
	Range string `json:"range"`

	// Quarantined counts blocks held back without being leased, today the ones
	// a client declined; it is disjoint from Used and both count against Size,
	// which saturates rather than wraps when a pool outgrows an int.
	Size        int `json:"size"`
	Used        int `json:"used"`
	Quarantined int `json:"quarantined"`
}

// Source is one plugin instance that holds leases.
// Implementations copy their state under their own lock, so both methods are
// safe to call concurrently with each other and with the packet path.
type Source interface {
	// Name identifies the instance as "<plugin> <first argument>", which is not
	// unique: two range plugins on one lease file report the same name.
	Name() string

	// Leases returns every lease the source holds, nil when it holds none.
	Leases() []Lease

	// Pools returns the pools the source allocates from, nil when it has none.
	Pools() []Pool
}

// Package-level because a setup function returns a handler and has nowhere to
// hand its instance to a consumer that is itself only a plugin.
var registry struct {
	mu      sync.Mutex
	sources []Source
}

// Register adds s to the registry, ignoring a nil s. Sources are not
// deduplicated: two instances of one plugin hold different leases.
func Register(s Source) {
	if s == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.sources = append(registry.sources, s)
}

// Sources returns a copy of the registered sources, in registration order.
func Sources() []Source {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return slices.Clone(registry.sources)
}

// Unregister removes the first registration of s, compared by identity.
// It exists for tests: nothing in the server unregisters.
func Unregister(s Source) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if i := slices.Index(registry.sources, s); i >= 0 {
		registry.sources = slices.Delete(registry.sources, i, i+1)
	}
}
