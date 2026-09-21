// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package dnsquery

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "simple name with trailing dot",
			input: "host.example.com.",
			want:  []byte{4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name:  "simple name without trailing dot",
			input: "host.example.com",
			want:  []byte{4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name:  "root",
			input: "",
			want:  []byte{0},
		},
		{
			name:    "empty label from doubled dot",
			input:   "host..example.com.",
			wantErr: true,
		},
		{
			name:    "empty label from leading dot",
			input:   ".host.example.com.",
			wantErr: true,
		},
		{
			name:    "label over 63 octets",
			input:   strings.Repeat("a", 64) + ".example.com.",
			wantErr: true,
		},
		{
			name:    "name over 255 octets on the wire",
			input:   strings.Repeat("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", 5) + "com.",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := encodeName(nil, tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("encodeName(%q) = %v, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("encodeName(%q) unexpected error: %v", tt.input, err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("encodeName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEncodeNameAppends(t *testing.T) {
	t.Parallel()
	dst := []byte{0xAA, 0xBB}
	got, err := encodeName(dst, "a.b.")
	if err != nil {
		t.Fatalf("encodeName: unexpected error: %v", err)
	}
	want := []byte{0xAA, 0xBB, 1, 'a', 1, 'b', 0}
	if string(got) != string(want) {
		t.Fatalf("encodeName appended = %v, want %v", got, want)
	}
}

func TestBuildQuery(t *testing.T) {
	t.Parallel()
	msg, err := buildQuery(0x1234, "host.example.com.", TypeA)
	if err != nil {
		t.Fatalf("buildQuery: unexpected error: %v", err)
	}
	if len(msg) < headerLen {
		t.Fatalf("buildQuery: message shorter than a header: %d bytes", len(msg))
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != 0x1234 {
		t.Errorf("id = %#x, want %#x", id, 0x1234)
	}
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags != 0 {
		t.Errorf("flags = %#x, want 0 (QR and RD both clear)", flags)
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qd)
	}
	if an := binary.BigEndian.Uint16(msg[6:8]); an != 0 {
		t.Errorf("ANCOUNT = %d, want 0", an)
	}
	qtype := binary.BigEndian.Uint16(msg[len(msg)-4 : len(msg)-2])
	if Type(qtype) != TypeA {
		t.Errorf("QTYPE = %d, want %d", qtype, TypeA)
	}
	qclass := binary.BigEndian.Uint16(msg[len(msg)-2:])
	if qclass != classIN {
		t.Errorf("QCLASS = %d, want %d", qclass, classIN)
	}
}

func TestBuildQueryRejectsBadName(t *testing.T) {
	t.Parallel()
	if _, err := buildQuery(1, "bad..name.", TypeA); err == nil {
		t.Fatal("buildQuery with an invalid name: want an error, got nil")
	}
}

// buildReplyHeader writes a 12-byte header with the QR bit set, RCODE 0,
// matching id, and the given question/answer counts.
func buildReplyHeader(id uint16, qdcount, ancount uint16) []byte {
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flagQR)
	binary.BigEndian.PutUint16(msg[4:6], qdcount)
	binary.BigEndian.PutUint16(msg[6:8], ancount)
	return msg
}

// appendQuestion appends one question (name, TypeA, class IN) to msg.
func appendQuestion(t *testing.T, msg []byte, name string) []byte {
	t.Helper()
	msg, err := encodeName(msg, name)
	if err != nil {
		t.Fatalf("encodeName(%q): %v", name, err)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(TypeA))
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg
}

// appendRecord appends one resource record (name, rrtype, TTL, rdata) to msg.
func appendRecord(t *testing.T, msg []byte, name string, rrtype Type, ttl uint32, rdata []byte) []byte {
	t.Helper()
	msg, err := encodeName(msg, name)
	if err != nil {
		t.Fatalf("encodeName(%q): %v", name, err)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(rrtype))
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func TestParseMessage(t *testing.T) {
	t.Parallel()

	t.Run("one A record", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(1, 1, 1)
		msg = appendQuestion(t, msg, "host.example.com.")
		msg = appendRecord(t, msg, "host.example.com.", TypeA, 60, []byte{192, 0, 2, 1})

		answer, err := parseMessage(1, msg)
		if err != nil {
			t.Fatalf("parseMessage: unexpected error: %v", err)
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
		if rec.Type != TypeA {
			t.Errorf("Type = %v, want %v", rec.Type, TypeA)
		}
		if rec.TTL != 60 {
			t.Errorf("TTL = %d, want 60", rec.TTL)
		}
		if string(rec.Data) != string([]byte{192, 0, 2, 1}) {
			t.Errorf("Data = %v, want %v", rec.Data, []byte{192, 0, 2, 1})
		}
	})

	t.Run("PTR record with compressed target", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(2, 1, 1)
		questionNameOff := len(msg)
		msg = appendQuestion(t, msg, "host.example.com.")

		// The PTR target reuses the question's name via a compression
		// pointer, exactly like a real name server would.
		ptrOwner := "1.2.0.192.in-addr.arpa."
		var err error
		msg, err = encodeName(msg, ptrOwner)
		if err != nil {
			t.Fatalf("encodeName(%q): %v", ptrOwner, err)
		}
		msg = binary.BigEndian.AppendUint16(msg, uint16(TypePTR))
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		pointer := uint16(pointerFlag)<<8 | uint16(questionNameOff)
		rdlenOff := len(msg)
		msg = binary.BigEndian.AppendUint16(msg, 0) // placeholder RDLENGTH
		rdataStart := len(msg)
		msg = binary.BigEndian.AppendUint16(msg, pointer)
		binary.BigEndian.PutUint16(msg[rdlenOff:rdlenOff+2], uint16(len(msg)-rdataStart))

		answer, err := parseMessage(2, msg)
		if err != nil {
			t.Fatalf("parseMessage: unexpected error: %v", err)
		}
		if len(answer.Records) != 1 {
			t.Fatalf("len(Records) = %d, want 1", len(answer.Records))
		}
		rec := answer.Records[0]
		if rec.Target != "host.example.com." {
			t.Errorf("Target = %q, want %q", rec.Target, "host.example.com.")
		}
	})

	t.Run("id mismatch", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(5, 0, 0)
		if _, err := parseMessage(6, msg); err == nil {
			t.Fatal("parseMessage with mismatched id: want an error, got nil")
		}
	})

	t.Run("QR bit clear", func(t *testing.T) {
		t.Parallel()
		msg := make([]byte, headerLen)
		binary.BigEndian.PutUint16(msg[0:2], 7)
		if _, err := parseMessage(7, msg); err == nil {
			t.Fatal("parseMessage with QR clear: want an error, got nil")
		}
	})

	t.Run("truncated message", func(t *testing.T) {
		t.Parallel()
		if _, err := parseMessage(1, []byte{0, 1, 2}); err == nil {
			t.Fatal("parseMessage on a 3-byte message: want an error, got nil")
		}
	})

	t.Run("truncated answer section", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(9, 0, 1)
		if _, err := parseMessage(9, msg); err == nil {
			t.Fatal("parseMessage claiming one answer with none present: want an error, got nil")
		}
	})

	t.Run("compression pointer loop", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(3, 0, 1)
		nameOff := len(msg)
		pointerToSelf := uint16(pointerFlag)<<8 | uint16(nameOff)
		msg = binary.BigEndian.AppendUint16(msg, pointerToSelf)
		msg = binary.BigEndian.AppendUint16(msg, uint16(TypeA))
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, 4)
		msg = append(msg, 192, 0, 2, 1)

		if _, err := parseMessage(3, msg); err == nil {
			t.Fatal("parseMessage on a self-referencing pointer: want an error, got nil")
		}
	})

	t.Run("question name runs off the end", func(t *testing.T) {
		t.Parallel()
		// qdcount claims one question, but the message ends at the header:
		// there is no name for skipQuestions to read.
		msg := buildReplyHeader(10, 1, 0)
		if _, err := parseMessage(10, msg); err == nil {
			t.Fatal("parseMessage with a missing question name: want an error, got nil")
		}
	})

	t.Run("question section missing type and class", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(11, 1, 0)
		msg = appendQuestion(t, msg, "host.example.com.")
		msg = msg[:len(msg)-4] // drop QTYPE and QCLASS
		if _, err := parseMessage(11, msg); err == nil {
			t.Fatal("parseMessage with a truncated question: want an error, got nil")
		}
	})

	t.Run("record header truncated", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(12, 0, 1)
		msg, err := encodeName(msg, "host.example.com.")
		if err != nil {
			t.Fatalf("encodeName: %v", err)
		}
		msg = append(msg, 0, 1) // two bytes of TYPE, nothing else
		if _, err := parseMessage(12, msg); err == nil {
			t.Fatal("parseMessage with a truncated record header: want an error, got nil")
		}
	})

	t.Run("record data truncated", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(13, 0, 1)
		msg, err := encodeName(msg, "host.example.com.")
		if err != nil {
			t.Fatalf("encodeName: %v", err)
		}
		msg = binary.BigEndian.AppendUint16(msg, uint16(TypeA))
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, 100) // RDLENGTH lies about what follows
		if _, err := parseMessage(13, msg); err == nil {
			t.Fatal("parseMessage with truncated record data: want an error, got nil")
		}
	})

	t.Run("PTR target fails to decode", func(t *testing.T) {
		t.Parallel()
		msg := buildReplyHeader(14, 0, 1)
		msg = appendRecord(t, msg, "1.2.0.192.in-addr.arpa.", TypePTR, 60, []byte{0xC0}) // truncated pointer
		if _, err := parseMessage(14, msg); err == nil {
			t.Fatal("parseMessage with an undecodable PTR target: want an error, got nil")
		}
	})
}

func TestReadName(t *testing.T) {
	t.Parallel()

	t.Run("simple name", func(t *testing.T) {
		t.Parallel()
		msg, err := encodeName(nil, "host.example.com.")
		if err != nil {
			t.Fatalf("encodeName: %v", err)
		}
		name, next, err := readName(msg, 0)
		if err != nil {
			t.Fatalf("readName: unexpected error: %v", err)
		}
		if name != "host.example.com." {
			t.Errorf("name = %q, want %q", name, "host.example.com.")
		}
		if next != len(msg) {
			t.Errorf("next = %d, want %d", next, len(msg))
		}
	})

	t.Run("lowercases mixed-case labels", func(t *testing.T) {
		t.Parallel()
		msg, err := encodeName(nil, "HoSt.Example.COM.")
		if err != nil {
			t.Fatalf("encodeName: %v", err)
		}
		name, _, err := readName(msg, 0)
		if err != nil {
			t.Fatalf("readName: unexpected error: %v", err)
		}
		if name != "host.example.com." {
			t.Errorf("name = %q, want %q", name, "host.example.com.")
		}
	})

	t.Run("compression pointer", func(t *testing.T) {
		t.Parallel()
		msg, err := encodeName(nil, "example.com.")
		if err != nil {
			t.Fatalf("encodeName: %v", err)
		}
		pointerOff := len(msg)
		pointer := uint16(pointerFlag) << 8
		msg = binary.BigEndian.AppendUint16(msg, pointer)

		name, next, err := readName(msg, pointerOff)
		if err != nil {
			t.Fatalf("readName: unexpected error: %v", err)
		}
		if name != "example.com." {
			t.Errorf("name = %q, want %q", name, "example.com.")
		}
		if next != pointerOff+2 {
			t.Errorf("next = %d, want %d (right after the pointer)", next, pointerOff+2)
		}
	})

	t.Run("pointer loop is bounded", func(t *testing.T) {
		t.Parallel()
		msg := make([]byte, 2)
		pointer := uint16(pointerFlag) << 8
		binary.BigEndian.PutUint16(msg, pointer)

		if _, _, err := readName(msg, 0); err == nil {
			t.Fatal("readName on a self-pointer: want an error, got nil")
		}
	})

	t.Run("name runs past end of message", func(t *testing.T) {
		t.Parallel()
		msg := []byte{5, 'h', 'o', 's', 't'} // label claims 5 bytes, only 4 follow
		if _, _, err := readName(msg, 0); err == nil {
			t.Fatal("readName on a truncated label: want an error, got nil")
		}
	})

	t.Run("offset past end of message", func(t *testing.T) {
		t.Parallel()
		msg := []byte{0}
		if _, _, err := readName(msg, 5); err == nil {
			t.Fatal("readName starting past the end of the message: want an error, got nil")
		}
	})

	t.Run("root name", func(t *testing.T) {
		t.Parallel()
		name, next, err := readName([]byte{0}, 0)
		if err != nil {
			t.Fatalf("readName: unexpected error: %v", err)
		}
		if name != "." {
			t.Errorf("name = %q, want %q", name, ".")
		}
		if next != 1 {
			t.Errorf("next = %d, want 1", next)
		}
	})

	t.Run("truncated compression pointer", func(t *testing.T) {
		t.Parallel()
		msg := []byte{pointerFlag} // the pointer's second byte never arrives
		if _, _, err := readName(msg, 0); err == nil {
			t.Fatal("readName on a one-byte pointer: want an error, got nil")
		}
	})
}

func TestRecordIPDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rec  Record
	}{
		{"wrong length for A", Record{Type: TypeA, Data: []byte{1, 2, 3}}},
		{"wrong length for AAAA", Record{Type: TypeAAAA, Data: []byte{1, 2, 3}}},
		{"not an address type", Record{Type: TypePTR, Data: []byte{1, 2, 3, 4}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := tt.rec.IP(); ok {
				t.Errorf("IP() on %+v: got ok=true, want false", tt.rec)
			}
		})
	}
}

func TestTypeString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		typ  Type
		want string
	}{
		{TypeA, "A"},
		{TypeSOA, "SOA"},
		{TypePTR, "PTR"},
		{TypeAAAA, "AAAA"},
		{TypeDHCID, "DHCID"},
		{Type(999), "999"},
	}
	for _, tt := range tests {
		if got := tt.typ.String(); got != tt.want {
			t.Errorf("Type(%d).String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}
