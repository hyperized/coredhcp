// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package dnsquery_test

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/coredhcp/coredhcp/test/all/internal/dnsquery"
)

// stubServer is a UDP name server that replies with a fixed message,
// ignoring whatever it was asked, and echoes the transaction id back so a
// real client's reply validation still passes.
type stubServer struct {
	conn    net.PacketConn
	addr    string
	stopped chan struct{}
}

// newStubServer starts a UDP listener on 127.0.0.1 that answers every query
// with buildReply(id) for the id it received.
func newStubServer(t *testing.T, buildReply func(id uint16) []byte) *stubServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	s := &stubServer{conn: conn, addr: conn.LocalAddr().String(), stopped: make(chan struct{})}
	go s.serve(buildReply)
	t.Cleanup(func() {
		_ = conn.Close()
		<-s.stopped
	})
	return s
}

func (s *stubServer) serve(buildReply func(id uint16) []byte) {
	defer close(s.stopped)
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[0:2])
		if _, err := s.conn.WriteTo(buildReply(id), addr); err != nil {
			return
		}
	}
}

// appendQuestion appends a question section (name, TypeA, class IN) built by
// hand, since the external test has no access to the package's own encoder.
func appendQuestion(msg []byte, labels ...string) []byte {
	for _, label := range labels {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1) // QTYPE A
	msg = binary.BigEndian.AppendUint16(msg, 1) // QCLASS IN
	return msg
}

// appendRecord appends one resource record built by hand, with a fixed TTL
// since none of these tests care what it is.
func appendRecord(msg []byte, rrtype uint16, rdata []byte, labels ...string) []byte {
	const ttl = 60
	for _, label := range labels {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, rrtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // class IN
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func TestAskRoundTrip(t *testing.T) {
	t.Parallel()

	server := newStubServer(t, func(id uint16) []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], id)
		binary.BigEndian.PutUint16(msg[2:4], 0x8000) // QR set, RCODE 0
		binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
		binary.BigEndian.PutUint16(msg[6:8], 1)      // ANCOUNT
		msg = appendQuestion(msg, "host", "example", "com")
		msg = appendRecord(msg, 1, []byte{192, 0, 2, 1}, "host", "example", "com")
		return msg
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	answer, err := dnsquery.Ask(ctx, server.addr, "host.example.com.", dnsquery.TypeA)
	if err != nil {
		t.Fatalf("Ask: unexpected error: %v", err)
	}
	if answer.RCode != 0 {
		t.Errorf("RCode = %d, want 0", answer.RCode)
	}
	if len(answer.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(answer.Records))
	}
	rec := answer.Records[0]
	if rec.Name != "host.example.com." {
		t.Errorf("Name = %q, want %q", rec.Name, "host.example.com.")
	}
	if rec.Type != dnsquery.TypeA {
		t.Errorf("Type = %v, want %v", rec.Type, dnsquery.TypeA)
	}
	addr, ok := rec.IP()
	if !ok {
		t.Fatal("IP() returned ok=false for an A record")
	}
	if want := netip.MustParseAddr("192.0.2.1"); addr != want {
		t.Errorf("IP() = %v, want %v", addr, want)
	}
}

func TestAskAAAA(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("2001:db8::1").To16()
	server := newStubServer(t, func(id uint16) []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], id)
		binary.BigEndian.PutUint16(msg[2:4], 0x8000)
		binary.BigEndian.PutUint16(msg[4:6], 1)
		binary.BigEndian.PutUint16(msg[6:8], 1)
		msg = appendQuestion(msg, "host", "example", "com")
		msg = appendRecord(msg, 28, ip, "host", "example", "com")
		return msg
	})

	answer, err := dnsquery.Ask(context.Background(), server.addr, "host.example.com.", dnsquery.TypeAAAA)
	if err != nil {
		t.Fatalf("Ask: unexpected error: %v", err)
	}
	if len(answer.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(answer.Records))
	}
	addr, ok := answer.Records[0].IP()
	if !ok {
		t.Fatal("IP() returned ok=false for an AAAA record")
	}
	if want := netip.MustParseAddr("2001:db8::1"); addr != want {
		t.Errorf("IP() = %v, want %v", addr, want)
	}
}

func TestAskDHCID(t *testing.T) {
	t.Parallel()

	dhcid := []byte{0x00, 0x01, 0x02, 0xAA, 0xBB, 0xCC}
	server := newStubServer(t, func(id uint16) []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], id)
		binary.BigEndian.PutUint16(msg[2:4], 0x8000)
		binary.BigEndian.PutUint16(msg[4:6], 1)
		binary.BigEndian.PutUint16(msg[6:8], 1)
		msg = appendQuestion(msg, "host", "example", "com")
		msg = appendRecord(msg, 49, dhcid, "host", "example", "com")
		return msg
	})

	answer, err := dnsquery.Ask(context.Background(), server.addr, "host.example.com.", dnsquery.TypeDHCID)
	if err != nil {
		t.Fatalf("Ask: unexpected error: %v", err)
	}
	if len(answer.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(answer.Records))
	}
	rec := answer.Records[0]
	if rec.Type != dnsquery.TypeDHCID {
		t.Errorf("Type = %v, want %v", rec.Type, dnsquery.TypeDHCID)
	}
	if len(rec.Data) == 0 {
		t.Error("Data is empty, want the raw DHCID RDATA")
	}
}

func TestAskPTR(t *testing.T) {
	t.Parallel()

	server := newStubServer(t, func(id uint16) []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], id)
		binary.BigEndian.PutUint16(msg[2:4], 0x8000)
		binary.BigEndian.PutUint16(msg[4:6], 1)
		binary.BigEndian.PutUint16(msg[6:8], 1)
		msg = appendQuestion(msg, "1", "2", "0", "192", "in-addr", "arpa")

		// Build the PTR record's owner name and RDATA by hand: the target
		// is not compressed here since the test only needs a plain name to
		// land in Record.Target.
		var rdata []byte
		for _, label := range []string{"host", "example", "com"} {
			rdata = append(rdata, byte(len(label)))
			rdata = append(rdata, label...)
		}
		rdata = append(rdata, 0)
		msg = appendRecord(msg, 12, rdata, "1", "2", "0", "192", "in-addr", "arpa")
		return msg
	})

	answer, err := dnsquery.Ask(context.Background(), server.addr, "1.2.0.192.in-addr.arpa.", dnsquery.TypePTR)
	if err != nil {
		t.Fatalf("Ask: unexpected error: %v", err)
	}
	if len(answer.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(answer.Records))
	}
	rec := answer.Records[0]
	if rec.Target != "host.example.com." {
		t.Errorf("Target = %q, want %q", rec.Target, "host.example.com.")
	}
}

func TestAskNoServer(t *testing.T) {
	t.Parallel()

	// Reserve a port and close it immediately, so nothing answers.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = dnsquery.Ask(ctx, addr, "host.example.com.", dnsquery.TypeA)
	if err == nil {
		t.Fatal("Ask against a closed port: want an error, got nil")
	}
}

func TestAskDialFailure(t *testing.T) {
	t.Parallel()
	// Too many colons for net.SplitHostPort: dialing fails before any packet
	// is sent.
	_, err := dnsquery.Ask(context.Background(), "bad:address:format", "host.example.com.", dnsquery.TypeA)
	if err == nil {
		t.Fatal("Ask with a malformed server address: want an error, got nil")
	}
}

func TestAskBadReply(t *testing.T) {
	t.Parallel()

	// The stub answers with someone else's transaction id, so parseMessage
	// rejects the reply and Ask has to surface that as its own error.
	server := newStubServer(t, func(id uint16) []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], id+1)
		binary.BigEndian.PutUint16(msg[2:4], 0x8000)
		return msg
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dnsquery.Ask(ctx, server.addr, "host.example.com.", dnsquery.TypeA)
	if err == nil {
		t.Fatal("Ask with a mismatched reply id: want an error, got nil")
	}
}

func TestAskRejectsInvalidName(t *testing.T) {
	t.Parallel()
	_, err := dnsquery.Ask(context.Background(), "127.0.0.1:53", "bad..name.", dnsquery.TypeA)
	if err == nil {
		t.Fatal("Ask with an invalid name: want an error, got nil")
	}
}

func TestTypeStringDHCID(t *testing.T) {
	t.Parallel()
	if got := dnsquery.TypeDHCID.String(); got != "DHCID" {
		t.Errorf("TypeDHCID.String() = %q, want %q", got, "DHCID")
	}
}
