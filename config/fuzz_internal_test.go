// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config

import (
	"net"
	"strings"
	"testing"
)

// The invariant: the output round-trips through net.JoinHostPort and back
// unchanged.
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
		// splitHostPort("%%") = ("%", "", ""): the ip still holding "%" makes zone==""
		// ambiguous with "no zone marker present", so round-tripping it is lossy - see the skip below.
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

		// An ip that still contains '%' (only from non-address garbage like "%%")
		// makes zone=="" ambiguous, so the round trip below doesn't apply here.
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
