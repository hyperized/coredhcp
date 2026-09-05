// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

// benchDUIDs pregenerates a large batch of distinct link-layer DUIDs so
// BenchmarkHandler6NewBinding can hand out a fresh one per iteration and the
// in-memory binding map genuinely grows instead of staying warm.
func benchDUIDs() []dhcpv6.DUID {
	const n = 200_000
	duids := make([]dhcpv6.DUID, n)
	for i := range duids {
		duids[i] = &dhcpv6.DUIDLL{
			HWType:        dhcpIana.HWTypeEthernet,
			LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
		}
	}
	return duids
}

// benchIAID is the IA_NA every benchmark request carries; only the DUID
// varies.
var benchIAID = [4]byte{0x00, 0x00, 0x00, 0x01}

// benchRequest builds a REQUEST for duid carrying one empty IA_NA, and the
// reply the plugin is asked to fill in.
func benchRequest(duid dhcpv6.DUID) (*dhcpv6.Message, *dhcpv6.Message) {
	req := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeRequest}
	req.AddOption(dhcpv6.OptClientID(duid))
	req.AddOption(&dhcpv6.OptIANA{IaId: benchIAID})
	resp := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeReply, TransactionID: req.TransactionID}
	return req, resp
}

// BenchmarkHandler6NewBinding drives the new-allocation path of Handler6
// with a fresh DUID every call: allocator lookup, sqlite insert, and the
// in-memory map write. The sqlite write goes to a real temp-dir file, so
// it's part of the honest per-binding cost being measured.
func BenchmarkHandler6NewBinding(b *testing.B) {
	b.ReportAllocs()

	// Handler6 logs one line per request at the default Info level;
	// silencing the console isolates the allocator/sqlite cost from
	// terminal I/O. The sqlite writes themselves still go to a real
	// temp-dir file below, so that part of the cost stays honest.
	logger.WithNoStdOutErr()

	db, err := loadDB(filepath.Join(b.TempDir(), "leases6.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8:1::"), net.ParseIP("2001:db8:1::ffff"))
	if err != nil {
		b.Fatal(err)
	}

	p := &pluginState{
		leasedb:   db,
		Records6:  make(map[string]*Record),
		declined:  make(map[string]time.Time),
		allocator: alloc,
		LeaseTime: time.Hour,
	}
	duids := benchDUIDs()

	i := 0
	for b.Loop() {
		req, resp := benchRequest(duids[i%len(duids)])
		p.Handler6(req, resp)
		i++
	}
}

// BenchmarkHandler6Renewal drives the renewal path of Handler6 with the
// same DUID and IAID on every call, including the sqlite update that
// persists the extended binding each time.
func BenchmarkHandler6Renewal(b *testing.B) {
	b.ReportAllocs()
	logger.WithNoStdOutErr()

	db, err := loadDB(filepath.Join(b.TempDir(), "leases6.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8:1::"), net.ParseIP("2001:db8:1::ffff"))
	if err != nil {
		b.Fatal(err)
	}

	p := &pluginState{
		leasedb:   db,
		Records6:  make(map[string]*Record),
		declined:  make(map[string]time.Time),
		allocator: alloc,
		LeaseTime: time.Hour,
	}
	duid := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}

	for b.Loop() {
		req, resp := benchRequest(duid)
		p.Handler6(req, resp)
	}
}
