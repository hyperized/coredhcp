// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
)

// FuzzHandleMsg4 fuzzes HandleMsg4's full receive path. buf goes through
// datagramBuf since HandleMsg4 returns it to bufpool (see handle_internal_test.go).
func FuzzHandleMsg4(f *testing.F) {
	discover, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		f.Fatalf("failed to build discover seed: %v", err)
	}
	f.Add(discover.ToBytes())

	request, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("192.0.2.5")))
	if err != nil {
		f.Fatalf("failed to build request seed: %v", err)
	}
	f.Add(request.ToBytes())

	full := discover.ToBytes()
	f.Add(full[:len(full)/2]) // truncated mid-options
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(_ *testing.T, buf []byte) {
		conn := &fakeConn4{}
		l := newTestListener4([]handler.Handler4{passthrough4}, conn)
		l.HandleMsg4(datagramBuf(buf), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	})
}

// FuzzHandleMsg6 also seeds a relayed solicit, so the relay
// decapsulate/re-encapsulate path gets fuzzed too.
func FuzzHandleMsg6(f *testing.F) {
	solicit, err := dhcpv6.NewSolicit(testMAC)
	if err != nil {
		f.Fatalf("failed to build solicit seed: %v", err)
	}
	f.Add(solicit.ToBytes())

	relayed, err := dhcpv6.EncapsulateRelay(solicit, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	if err != nil {
		f.Fatalf("failed to build relayed seed: %v", err)
	}
	f.Add(relayed.ToBytes())

	full := solicit.ToBytes()
	f.Add(full[:len(full)/2]) // truncated mid-options
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(_ *testing.T, buf []byte) {
		conn := &fakeConn6{}
		l := newTestListener6([]handler.Handler6{passthrough6}, conn)
		l.HandleMsg6(datagramBuf(buf), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
	})
}
