// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"net/netip"

	"github.com/coredhcp/coredhcp/leases"
)

// This file makes an instance of the file plugin readable: it implements
// leases.Source over the same reservation map the packet path uses, under the
// same lock, so an API or a UI can list the static mappings alongside the
// dynamic leases of a pool plugin. setupFile registers the instance; see
// plugin.go.

// Name reports this instance as "file <lease file>", which is what
// distinguishes the server4 and server6 instances of the plugin, and two
// instances reading different files.
func (s *pluginState) Name() string {
	return s.name
}

// Leases returns every reservation loaded from the lease file.
//
// They are all static: an operator wrote them down, they never expire, and a
// client cannot release one. Expires is left zero, which is what Static means
// on the reading side.
//
// With autorefresh on, the map is replaced wholesale when the file changes, so
// a snapshot is a coherent view of one revision of the file rather than a
// blend of two.
func (s *pluginState) Leases() []leases.Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]leases.Lease, 0, len(s.recs))
	for mac, addr := range s.recs {
		out = append(out, leases.Lease{
			Family:  s.family,
			Client:  mac,
			Address: netip.PrefixFrom(addr, addr.BitLen()),
			Static:  true,
			Source:  s.name,
		})
	}
	return out
}

// Pools returns nil. This plugin serves addresses an operator assigned by
// hand; it manages no address space of its own, and reporting a pool of the
// reservations it happens to hold would invite a reader to compute a
// utilisation that means nothing.
func (s *pluginState) Pools() []leases.Pool {
	return nil
}

// familyOf maps the protocol flag setupFile is called with to the number a
// lease reader uses.
func familyOf(v6 bool) uint8 {
	if v6 {
		return 6
	}
	return 4
}
