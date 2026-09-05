// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
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

// FuzzParseDHCPv4Records fuzzes parseDHCPRecords directly with arbitrary
// bytes for the MAC-keyed v4 case, sidestepping the filesystem so the fuzz
// engine spends its time on the line/field/address parsing logic. The
// invariant is: return an error or a result, never panic; and on success
// every returned address must actually be a valid IPv4 address.
func FuzzParseDHCPv4Records(f *testing.F) {
	f.Add([]byte(validRecordsSeedV4))
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPRecords(bytes.NewReader(data), false, keyMAC)
		if err != nil {
			return
		}
		for mac, addr := range records {
			if _, err := net.ParseMAC(mac); err != nil {
				t.Fatalf("parseDHCPRecords(keyMAC) returned a non-MAC key %q: %v", mac, err)
			}
			if !addr.Is4() {
				t.Fatalf("parseDHCPRecords(keyMAC) returned a non-IPv4 address for %q: %v", mac, addr)
			}
		}
	})
}

// FuzzParseDHCPv6Records mirrors FuzzParseDHCPv4Records for the IPv6,
// MAC-keyed case.
func FuzzParseDHCPv6Records(f *testing.F) {
	f.Add([]byte(validRecordsSeedV6))
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPRecords(bytes.NewReader(data), true, keyMAC)
		if err != nil {
			return
		}
		for mac, addr := range records {
			if _, err := net.ParseMAC(mac); err != nil {
				t.Fatalf("parseDHCPRecords(keyMAC) returned a non-MAC key %q: %v", mac, err)
			}
			if !addr.Is6() {
				t.Fatalf("parseDHCPRecords(keyMAC) returned a non-IPv6 address for %q: %v", mac, addr)
			}
		}
	})
}

// duidRecordsSeeds cover the hex-form variations key:duid accepts, plus the
// over-long DUID that has to be rejected rather than hex encoded onto every
// request.
var duidRecordsSeeds = []string{
	"0x00030001aabbccddeeff 2001:db8::10:1\n",
	"00:03:00:01:aa:bb:cc:dd:ee:ff 2001:db8::10:1\n",
	"00030001AABBCCDDEEFF 2001:db8::10:1\n",
	strings.Repeat("aa", maxDUIDLen+1) + " 2001:db8::10:1\n",
	"0xzz 2001:db8::10:1\n",
	"0xabc 2001:db8::10:1\n",
	"0x 2001:db8::10:1\n",
}

// FuzzParseDHCPRecordsDUID fuzzes parseDHCPRecords for key:duid. Besides the
// no-panic invariant, every returned key must be the lowercase hex encoding
// parseDUIDField promises, at even length.
func FuzzParseDHCPRecordsDUID(f *testing.F) {
	for _, s := range duidRecordsSeeds {
		f.Add([]byte(s))
	}
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPRecords(bytes.NewReader(data), true, keyDUID)
		if err != nil {
			return
		}
		for key, addr := range records {
			assertValidHexKey(t, key)
			if !addr.Is6() {
				t.Fatalf("parseDHCPRecords(keyDUID) returned a non-IPv6 address for %q: %v", key, addr)
			}
		}
	})
}

// clientIDRecordsSeeds cover the hex forms and the text: form key:client-id
// accepts.
var clientIDRecordsSeeds = []string{
	"0x01aabbccddeeff 10.0.0.1\n",
	"01:aa:bb:cc:dd:ee:ff 10.0.0.1\n",
	"text:printer-2nd-floor 10.0.0.2\n",
	"text: 10.0.0.3\n",
	"0xzz 10.0.0.4\n",
	"0xabc 10.0.0.5\n",
}

// FuzzParseDHCPRecordsClientID mirrors FuzzParseDHCPRecordsDUID for
// key:client-id.
func FuzzParseDHCPRecordsClientID(f *testing.F) {
	for _, s := range clientIDRecordsSeeds {
		f.Add([]byte(s))
	}
	for _, s := range fuzzRecordsSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := parseDHCPRecords(bytes.NewReader(data), false, keyClientID)
		if err != nil {
			return
		}
		for key, addr := range records {
			assertValidHexKey(t, key)
			if !addr.Is4() {
				t.Fatalf("parseDHCPRecords(keyClientID) returned a non-IPv4 address for %q: %v", key, addr)
			}
		}
	})
}

// assertValidHexKey checks the invariant every key-mode parser promises for
// a canonical map key: lowercase hex, so it decodes and round-trips cleanly.
func assertValidHexKey(t *testing.T, key string) {
	t.Helper()
	if len(key)%2 != 0 {
		t.Fatalf("key %q has odd length", key)
	}
	if key != strings.ToLower(key) {
		t.Fatalf("key %q is not lowercase", key)
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Fatalf("key %q is not valid hex: %v", key, err)
	}
}
