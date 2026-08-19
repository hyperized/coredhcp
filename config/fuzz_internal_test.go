// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config

import (
	"net"
	"strings"
	"testing"
)

// FuzzSplitHostPort feeds arbitrary strings to splitHostPort. Beyond "never
// panics", the invariant checked here is a round trip: re-joining the
// returned (ip, zone, port) with net.JoinHostPort and splitting the result
// again must reproduce the exact same triple with no error.
//
// This holds because splitHostPort's own splitting logic is exactly "split
// host:port with net.SplitHostPort (falling back to a synthetic :0 port),
// then cut the zone off the host at the last '%'" - net.JoinHostPort is the
// inverse of net.SplitHostPort (it brackets a host containing ':' and always
// emits a "host:port" or "[host]:port" shape), so reassembling ip+"%"+zone
// (when zone is set) and joining it with port must parse back to the same
// pieces. Verified against every case in TestSplitHostPort before fuzzing.
func FuzzSplitHostPort(f *testing.F) {
	seeds := []string{
		"0.0.0.0:67",
		"192.0.2.0",
		"192.0.2.9%eth0",
		"0.0.0.0%eth0:67",
		"0.0.0.0:20%eth0:67",
		"2001:db8::1:547",
		"[::]:547",
		"[fe80::1%eth0]",
		"[fe80::1]:eth1",
		"fe80::1%eth0:547",
		"fe80::1%eth0",
		"[2001:db8::2]47",
		"[ff02::1:2]%srv_u:547",
		":http",
		"%eth0:80",
		"%eth0",
		"fe80::1]:80",
		"fe80::1%eth0]",
		"",
		"a%b%c:80",
		"[a:b:c%foo]:5",
		// Found by fuzzing: splitHostPort("%%") = ("%", "", "") - the
		// returned ip still holds a literal '%'. That is indistinguishable,
		// from the returned triple alone, from an ip that never had a zone
		// marker at all (also zone==""), so round-tripping it is inherently
		// lossy. See the skip below.
		"%%",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, hostport string) {
		ip, zone, port, err := splitHostPort(hostport)
		if err != nil {
			return
		}

		// A returned ip that still contains a literal '%' (only reachable
		// through non-address garbage such as "%%", never through a real
		// listen address) makes zone=="" ambiguous: it could mean "no zone
		// marker was present" or "the zone marker's content was empty".
		// splitHostPort's return values can't tell those apart, so the
		// round trip below does not apply; only "no panic" is checked here.
		if strings.ContainsRune(ip, '%') {
			return
		}

		hostPart := ip
		if zone != "" {
			hostPart = ip + "%" + zone
		}
		recombined := net.JoinHostPort(hostPart, port)

		ip2, zone2, port2, err2 := splitHostPort(recombined)
		if err2 != nil {
			t.Fatalf("splitHostPort(%q) = (%q,%q,%q); recombined %q does not split cleanly: %v", hostport, ip, zone, port, recombined, err2)
		}
		if ip2 != ip || zone2 != zone || port2 != port {
			t.Fatalf("splitHostPort(%q) = (%q,%q,%q); round trip via %q gave (%q,%q,%q)", hostport, ip, zone, port, recombined, ip2, zone2, port2)
		}
	})
}
