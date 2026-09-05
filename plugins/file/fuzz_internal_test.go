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

const validRecordsSeedV4 = "00:11:22:33:44:aa 192.0.2.100\n" +
	" 11:BB:33:DD:55:FF \t 192.0.2.101  # trailing comment\n" +
	" # standalone comment\n"

const validRecordsSeedV6 = "00:11:22:33:44:aa 2001:db8::10:1\n" +
	" 11:BB:33:DD:55:FF \t 2001:db8::10:2  # trailing comment\n" +
	" # standalone comment\n"

// Exercises the malformed-input branches (missing field, bad MAC, bad IP,
// wrong family) already covered for the exported loaders in plugin_external_test.go.
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

// Sidesteps the filesystem so fuzzing spends its budget on parsing logic.
// Must never panic; on success every address must be a valid IPv4 address.
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

// Includes an over-long DUID, which must be rejected rather than hex-encoded regardless.
var duidRecordsSeeds = []string{
	"0x00030001aabbccddeeff 2001:db8::10:1\n",
	"00:03:00:01:aa:bb:cc:dd:ee:ff 2001:db8::10:1\n",
	"00030001AABBCCDDEEFF 2001:db8::10:1\n",
	strings.Repeat("aa", maxDUIDLen+1) + " 2001:db8::10:1\n",
	"0xzz 2001:db8::10:1\n",
	"0xabc 2001:db8::10:1\n",
	"0x 2001:db8::10:1\n",
}

// Every returned key must be the lowercase, even-length hex encoding parseDUIDField promises.
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

var clientIDRecordsSeeds = []string{
	"0x01aabbccddeeff 10.0.0.1\n",
	"01:aa:bb:cc:dd:ee:ff 10.0.0.1\n",
	"text:printer-2nd-floor 10.0.0.2\n",
	"text: 10.0.0.3\n",
	"0xzz 10.0.0.4\n",
	"0xabc 10.0.0.5\n",
}

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

// Every key-mode parser promises lowercase, round-trippable hex as its canonical map key.
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
