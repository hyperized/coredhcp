// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"bytes"
	"net"
	"testing"
)

// validRecordsSeedV4/V6 are well-formed leases file bodies for each parser.
const validRecordsSeedV4 = "00:11:22:33:44:aa 192.0.2.100\n" +
	" 11:BB:33:DD:55:FF \t 192.0.2.101  # trailing comment\n" +
	" # standalone comment\n"

const validRecordsSeedV6 = "00:11:22:33:44:aa 2001:db8::10:1\n" +
	" 11:BB:33:DD:55:FF \t 2001:db8::10:2  # trailing comment\n" +
	" # standalone comment\n"

// fuzzRecordsSeeds are shared between the v4 and v6 fuzz targets: each
// exercises the same malformed-input branches (missing field, bad MAC, bad
// IP, wrong address family) that plugin_external_test.go's table already
// covers for the exported loaders.
var fuzzRecordsSeeds = []string{
	"",
	"foo\n",
	"abcd 192.0.2.102\n",
	"22:33:44:55:66:77 bcde\n",
	"00:11:22:33:44:55 2001:db8::10:1\n",
	"00:11:22:33:44:55 192.0.2.100\n",
	"aa:11:11:11:11:11 1.2.3.4\nAA:11:11:11:11:11 5.6.7.8\n",
	"\x00\x01\x02 not-a-line-at-all\xff",
}

// FuzzParseDHCPv4Records fuzzes the unexported parser directly with
// arbitrary bytes, sidestepping the filesystem so the fuzz engine spends its
// time on the line/field/address parsing logic. The invariant is: return an
// error or a result, never panic; and on success every returned address must
// actually be a valid IPv4 address (parseDHCPv4Records' own contract).
func FuzzParseDHCPv4Records(f *testing.F) {
	f.Add([]byte(validRecordsSeedV4))
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPv4Records(bytes.NewReader(data))
		if err != nil {
			return
		}
		for mac, addr := range records {
			if _, err := net.ParseMAC(mac); err != nil {
				t.Fatalf("parseDHCPv4Records returned a non-MAC key %q: %v", mac, err)
			}
			if !addr.Is4() {
				t.Fatalf("parseDHCPv4Records returned a non-IPv4 address for %q: %v", mac, addr)
			}
		}
	})
}

// FuzzParseDHCPv6Records mirrors FuzzParseDHCPv4Records for the IPv6 parser.
func FuzzParseDHCPv6Records(f *testing.F) {
	f.Add([]byte(validRecordsSeedV6))
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPv6Records(bytes.NewReader(data))
		if err != nil {
			return
		}
		for mac, addr := range records {
			if _, err := net.ParseMAC(mac); err != nil {
				t.Fatalf("parseDHCPv6Records returned a non-MAC key %q: %v", mac, err)
			}
			if !addr.Is6() {
				t.Fatalf("parseDHCPv6Records returned a non-IPv6 address for %q: %v", mac, addr)
			}
		}
	})
}
