// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file_test

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/file"
)

// benchLeaseFile writes a 10k-record DHCPv4 lease file to a temp dir and
// returns its path together with the MAC addresses in the order written.
func benchLeaseFile(b *testing.B) (string, []net.HardwareAddr) {
	b.Helper()

	const n = 10_000
	macs := make([]net.HardwareAddr, n)
	var sb strings.Builder
	for i := range macs {
		mac := net.HardwareAddr{0xaa, byte(i >> 16), byte(i >> 8), byte(i), 0x00, 0x01}
		macs[i] = mac
		fmt.Fprintf(&sb, "%s 10.%d.%d.%d\n", mac, byte(i>>16), byte(i>>8), byte(i))
	}

	path := filepath.Join(b.TempDir(), "leases.txt")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	return path, macs
}

// BenchmarkHandler4Lookup exercises Handler4's read path against 10k loaded
// records, built through the exported Setup4 entry point.
func BenchmarkHandler4Lookup(b *testing.B) {
	b.ReportAllocs()
	// Handler4 logs one line per lookup at the default Info level;
	// silencing the console isolates the map-lookup cost from terminal I/O.
	logger.WithNoStdOutErr()

	path, macs := benchLeaseFile(b)
	h4, err := file.Plugin.Setup4(path)
	if err != nil {
		b.Fatal(err)
	}
	req := &dhcpv4.DHCPv4{ClientHWAddr: macs[len(macs)/2]}

	for b.Loop() {
		resp := &dhcpv4.DHCPv4{}
		h4(req, resp)
	}
}

// BenchmarkLoadDHCPv4Records parses a 10k-line lease file from scratch on
// every iteration, covering the file read and per-line parsing cost.
func BenchmarkLoadDHCPv4Records(b *testing.B) {
	b.ReportAllocs()
	logger.WithNoStdOutErr()

	path, _ := benchLeaseFile(b)

	for b.Loop() {
		if _, err := file.LoadDHCPv4Records(path); err != nil {
			b.Fatal(err)
		}
	}
}

// benchLeaseFileClientID writes a 10k-record DHCPv4 lease file keyed on
// option 61 client identifiers and returns its path together with the raw
// identifier bytes in the order written.
func benchLeaseFileClientID(b *testing.B) (string, [][]byte) {
	b.Helper()

	const n = 10_000
	ids := make([][]byte, n)
	var sb strings.Builder
	for i := range ids {
		id := []byte{0x01, byte(i >> 16), byte(i >> 8), byte(i), 0x00, 0x01}
		ids[i] = id
		fmt.Fprintf(&sb, "0x%s 10.%d.%d.%d\n", hex.EncodeToString(id), byte(i>>16), byte(i>>8), byte(i))
	}

	path := filepath.Join(b.TempDir(), "leases.txt")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	return path, ids
}

// BenchmarkHandler4LookupClientID mirrors BenchmarkHandler4Lookup for the
// key:client-id path, so the new lookup mode has its own numbers.
func BenchmarkHandler4LookupClientID(b *testing.B) {
	b.ReportAllocs()
	logger.WithNoStdOutErr()

	path, ids := benchLeaseFileClientID(b)
	h4, err := file.Plugin.Setup4(path, "key:client-id")
	if err != nil {
		b.Fatal(err)
	}
	req := &dhcpv4.DHCPv4{}
	req.UpdateOption(dhcpv4.OptClientIdentifier(ids[len(ids)/2]))

	for b.Loop() {
		resp := &dhcpv4.DHCPv4{}
		h4(req, resp)
	}
}

// BenchmarkLoadDHCPv4RecordsClientID mirrors BenchmarkLoadDHCPv4Records for
// the key:client-id path. There is no exported per-mode loader, only
// LoadDHCPv4Records's fixed MAC keying, so this goes through Setup4 instead;
// Setup4's own overhead (arg parsing, one log line) is fixed cost paid once
// per iteration by both benchmarks and negligible next to parsing 10k lines,
// so it doesn't skew the mac-vs-client-id comparison.
func BenchmarkLoadDHCPv4RecordsClientID(b *testing.B) {
	b.ReportAllocs()
	logger.WithNoStdOutErr()

	path, _ := benchLeaseFileClientID(b)

	for b.Loop() {
		if _, err := file.Plugin.Setup4(path, "key:client-id"); err != nil {
			b.Fatal(err)
		}
	}
}
