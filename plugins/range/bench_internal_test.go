// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

// benchMACs pregenerates a large batch of distinct hardware addresses so
// BenchmarkHandler4NewLease can hand out a fresh one per iteration and the
// in-memory lease map genuinely grows instead of staying warm.
func benchMACs() []net.HardwareAddr {
	const n = 200_000
	macs := make([]net.HardwareAddr, n)
	for i := range macs {
		macs[i] = net.HardwareAddr{0x02, 0x00, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
	}
	return macs
}

// BenchmarkHandler4NewLease drives the new-allocation path of Handler4 with
// a fresh MAC every call: allocator lookup, sqlite insert, and the in-memory
// map write. The sqlite write goes to a real temp-dir file, so it's part of
// the honest per-lease cost being measured.
func BenchmarkHandler4NewLease(b *testing.B) {
	b.ReportAllocs()

	// Handler4 logs one line per request at the default Info level;
	// silencing the console isolates the allocator/sqlite cost from
	// terminal I/O. The sqlite writes themselves still go to a real
	// temp-dir file below, so that part of the cost stays honest.
	logger.WithNoStdOutErr()

	db, err := loadDB(filepath.Join(b.TempDir(), "leases.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv4Allocator(net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255))
	if err != nil {
		b.Fatal(err)
	}

	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: alloc,
		LeaseTime: time.Hour,
	}
	macs := benchMACs()

	i := 0
	for b.Loop() {
		req := &dhcpv4.DHCPv4{ClientHWAddr: macs[i%len(macs)]}
		resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}
		pl.Handler4(req, resp)
		i++
	}
}

// BenchmarkHandler4Renewal drives the renewal path of Handler4 with the same
// MAC on every call, including the sqlite update that persists the extended
// lease each time.
func BenchmarkHandler4Renewal(b *testing.B) {
	b.ReportAllocs()
	logger.WithNoStdOutErr()

	db, err := loadDB(filepath.Join(b.TempDir(), "leases.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv4Allocator(net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 255))
	if err != nil {
		b.Fatal(err)
	}

	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: alloc,
		LeaseTime: time.Hour,
	}
	req := &dhcpv4.DHCPv4{ClientHWAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}}

	for b.Loop() {
		resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}
		pl.Handler4(req, resp)
	}
}
