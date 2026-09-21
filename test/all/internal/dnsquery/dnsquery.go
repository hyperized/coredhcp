// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package dnsquery is a minimal DNS client for end-to-end tests. It knows
// just enough of RFC 1035 to send one question to one name server over UDP
// and read back the answer section, including record types net.Resolver has
// no way to ask for, such as DHCID (type 49). It exists for the ddns
// plugin's test suite, which has to confirm that a Knot server actually
// holds the A, AAAA, PTR and DHCID records the plugin wrote, not merely that
// some resolver eventually agrees.
package dnsquery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Type is a DNS resource record type.
type Type uint16

// These are the record types Ask can request and Record.Type can carry.
const (
	TypeA     Type = 1
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeAAAA  Type = 28
	TypeDHCID Type = 49
)

// String returns the record type's mnemonic, or its number when it has none.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeAAAA:
		return "AAAA"
	case TypeDHCID:
		return "DHCID"
	default:
		return strconv.Itoa(int(t))
	}
}

// Record is one resource record from the answer section.
type Record struct {
	Name   string // owner name, lowercased, with a trailing dot
	Type   Type
	TTL    uint32
	Data   []byte // the RDATA exactly as it arrived, with no name decompression applied
	Target string // decoded name carried by a PTR record's RDATA, lowercased with a trailing dot; empty for every other type
}

// IP returns the address in an A or AAAA record.
func (r Record) IP() (netip.Addr, bool) {
	switch {
	case r.Type == TypeA && len(r.Data) == 4:
		return netip.AddrFrom4([4]byte(r.Data)), true
	case r.Type == TypeAAAA && len(r.Data) == 16:
		return netip.AddrFrom16([16]byte(r.Data)), true
	default:
		return netip.Addr{}, false
	}
}

// Answer is what a name server sent back.
type Answer struct {
	RCode   uint8
	Records []Record // answer section only; authority and additional are discarded
}

const (
	classIN   = 1
	headerLen = 12

	flagQR = 1 << 15

	maxLabelLen = 63
	maxNameLen  = 255

	pointerFlag    = 0xC0
	maxPointerHops = 128

	maxUDPMessage  = 4096
	defaultTimeout = 3 * time.Second
)

// Ask sends one question to server (host:port) and returns the answer section.
func Ask(ctx context.Context, server, name string, qtype Type) (Answer, error) {
	id, err := randomID()
	if err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w; no random source is available to pick a transaction id", server, name, qtype, err)
	}
	query, err := buildQuery(id, name, qtype)
	if err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w", server, name, qtype, err)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w; check that the name server is reachable and holds the zone", server, name, qtype, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultTimeout)
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w", server, name, qtype, err)
	}

	if _, err = conn.Write(query); err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w; check that the name server is reachable and holds the zone", server, name, qtype, err)
	}

	buf := make([]byte, maxUDPMessage)
	n, err := conn.Read(buf)
	if err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w; check that the name server is reachable and holds the zone", server, name, qtype, err)
	}

	answer, err := parseMessage(id, buf[:n])
	if err != nil {
		return Answer{}, fmt.Errorf("querying %s for %s %s failed: %w; check that the name server actually answered this question", server, name, qtype, err)
	}
	return answer, nil
}

// randomID picks a transaction id from crypto/rand, so a query cannot be
// guessed by anything watching the wire.
func randomID() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// encodeName appends the wire form of name to dst and returns the result.
func encodeName(dst []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	start := len(dst)
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if label == "" {
				return nil, fmt.Errorf("encoding %q: it has an empty label; remove the doubled or leading dot", name)
			}
			if len(label) > maxLabelLen {
				return nil, fmt.Errorf("encoding %q: label %q is %d octets, over the %d limit; use a shorter label", name, label, len(label), maxLabelLen)
			}
			// #nosec G115 -- len(label) was just checked against maxLabelLen (63).
			dst = append(dst, byte(len(label)))
			dst = append(dst, label...)
		}
	}
	dst = append(dst, 0)
	if len(dst)-start > maxNameLen {
		return nil, fmt.Errorf("encoding %q: name is %d octets on the wire, over the %d limit; use a shorter name", name, len(dst)-start, maxNameLen)
	}
	return dst, nil
}

// buildQuery returns a wire-format DNS message with one question and the RD
// bit clear: the servers this package talks to are asked directly and are
// authoritative for the zone, so no recursion is wanted.
func buildQuery(id uint16, name string, qtype Type) ([]byte, error) {
	msg := make([]byte, headerLen, headerLen+len(name)+8)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	msg, err := encodeName(msg, name)
	if err != nil {
		return nil, err
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(qtype))
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg, nil
}

// header is the fixed part of a DNS message, decoded into the fields
// parseMessage needs.
type header struct {
	id      uint16
	qr      bool
	rcode   uint8
	qdcount uint16
	ancount uint16
}

// parseHeader reads the 12-byte DNS header at the start of msg.
func parseHeader(msg []byte) (header, error) {
	if len(msg) < headerLen {
		return header{}, errors.New("message is shorter than a DNS header")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	return header{
		id:      binary.BigEndian.Uint16(msg[0:2]),
		qr:      flags&flagQR != 0,
		rcode:   uint8(flags & 0x0f),
		qdcount: binary.BigEndian.Uint16(msg[4:6]),
		ancount: binary.BigEndian.Uint16(msg[6:8]),
	}, nil
}

// parseMessage validates msg as a reply to id and returns its answer
// section.
func parseMessage(id uint16, msg []byte) (Answer, error) {
	hdr, err := parseHeader(msg)
	if err != nil {
		return Answer{}, err
	}
	if hdr.id != id {
		return Answer{}, fmt.Errorf("reply id %d does not match query id %d; another query's answer arrived on this socket", hdr.id, id)
	}
	if !hdr.qr {
		return Answer{}, errors.New("message has the QR bit clear; it is a query, not a reply")
	}
	off, err := skipQuestions(msg, headerLen, hdr.qdcount)
	if err != nil {
		return Answer{}, err
	}
	records, err := parseRecords(msg, off, hdr.ancount)
	if err != nil {
		return Answer{}, err
	}
	return Answer{RCode: hdr.rcode, Records: records}, nil
}

// skipQuestions advances past the n questions starting at off and returns
// the offset of whatever follows.
func skipQuestions(msg []byte, off int, n uint16) (int, error) {
	for range n {
		_, next, err := readName(msg, off)
		if err != nil {
			return 0, err
		}
		if next+4 > len(msg) {
			return 0, errors.New("question section is truncated")
		}
		off = next + 4 // QTYPE and QCLASS
	}
	return off, nil
}

// parseRecords reads the n resource records starting at off.
func parseRecords(msg []byte, off int, n uint16) ([]Record, error) {
	records := make([]Record, 0, n)
	for range n {
		rec, next, err := parseRecord(msg, off)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
		off = next
	}
	return records, nil
}

// parseRecord reads one resource record starting at off and returns it
// along with the offset of whatever follows it.
func parseRecord(msg []byte, off int) (Record, int, error) {
	name, off, err := readName(msg, off)
	if err != nil {
		return Record{}, 0, err
	}
	if off+10 > len(msg) {
		return Record{}, 0, errors.New("resource record header is truncated")
	}
	rrtype := Type(binary.BigEndian.Uint16(msg[off : off+2]))
	ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10
	if off+rdlen > len(msg) {
		return Record{}, 0, errors.New("resource record data is truncated")
	}
	rec := Record{
		Name: name,
		Type: rrtype,
		TTL:  ttl,
		Data: append([]byte(nil), msg[off:off+rdlen]...),
	}
	if rrtype == TypePTR {
		target, _, err := readName(msg, off)
		if err != nil {
			return Record{}, 0, fmt.Errorf("decoding the PTR target owned by %q: %w", name, err)
		}
		rec.Target = target
	}
	return rec, off + rdlen, nil
}

// readName reads a possibly compressed domain name starting at off and
// returns it lowercased with a trailing dot, plus the offset in msg right
// after the name as it was written at off (a pointer counts as two bytes,
// however far it jumps). Pointer chasing is capped at maxPointerHops so a
// pointer loop returns an error instead of spinning forever.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	pos := off
	end := -1
	hops := 0
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("name runs past the end of the message")
		}
		length := msg[pos]
		switch {
		case length == 0:
			pos++
			if end == -1 {
				end = pos
			}
			return joinLabels(labels), end, nil
		case length&pointerFlag == pointerFlag:
			target, err := followPointer(msg, pos)
			if err != nil {
				return "", 0, err
			}
			if end == -1 {
				end = pos + 2
			}
			hops++
			if hops > maxPointerHops {
				return "", 0, errors.New("too many compression pointers; the message likely loops")
			}
			pos = target
		default:
			label, next, err := readLabel(msg, pos, length)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, label)
			pos = next
		}
	}
}

// followPointer decodes the two-byte compression pointer at pos and returns
// the offset it points to.
func followPointer(msg []byte, pos int) (int, error) {
	if pos+1 >= len(msg) {
		return 0, errors.New("compression pointer is truncated")
	}
	return int(msg[pos]&^pointerFlag)<<8 | int(msg[pos+1]), nil
}

// readLabel reads one length-prefixed label at pos, where length is
// msg[pos], and returns it along with the offset right after it.
func readLabel(msg []byte, pos int, length byte) (string, int, error) {
	start := pos + 1
	end := start + int(length)
	if end > len(msg) {
		return "", 0, errors.New("label runs past the end of the message")
	}
	return string(msg[start:end]), end, nil
}

// joinLabels turns a decoded label sequence into the dotted, lowercased,
// trailing-dot form used throughout this package.
func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.ToLower(strings.Join(labels, ".")) + "."
}
