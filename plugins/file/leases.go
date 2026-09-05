// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"net/netip"

	"github.com/coredhcp/coredhcp/leases"
)

// This file implements leases.Source over the same reservation map the packet
// path uses, under the same lock.

// Name reports this instance as "file <lease file>", which is what
// distinguishes the server4 and server6 instances of the plugin, and two
// instances reading different files.
func (s *pluginState) Name() string {
	return s.name
}

// Leases returns every reservation loaded from the lease file.
//
// All static, so Expires is left zero. With autorefresh on the map is replaced
// wholesale, so a snapshot is one revision of the file, never a blend of two.
func (s *pluginState) Leases() []leases.Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]leases.Lease, 0, len(s.recs))
	for key, addr := range s.recs {
		out = append(out, leases.Lease{
			Family:  s.family,
			Client:  key,
			Address: netip.PrefixFrom(addr, addr.BitLen()),
			Static:  true,
			Source:  s.name,
		})
	}
	return out
}

// Pools returns nil: the plugin manages no address space of its own, and a
// pool of hand-written reservations would yield a meaningless utilisation.
func (s *pluginState) Pools() []leases.Pool {
	return nil
}

func familyOf(v6 bool) uint8 {
	if v6 {
		return 6
	}
	return 4
}
