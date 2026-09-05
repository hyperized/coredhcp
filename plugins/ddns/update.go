// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// opCodeUpdate is the UPDATE opcode of RFC 2136. It reuses the header of a
// query with different meanings for the four section counts: zone,
// prerequisite, update and additional.
const opCodeUpdate = dnsmessage.OpCode(5)

// change is one record in the update section.
//
// Class says what to do with it. IN adds the record. ANY with no RDATA and a
// TTL of zero deletes every record of that type at that name, which is the
// "Delete an RRset" form of RFC 2136 section 2.5.2.
type change struct {
	name  string
	rtype dnsmessage.Type
	class dnsmessage.Class
	ttl   uint32
	data  []byte
}

// deleteRRset returns the change that removes every record of rtype at name.
func deleteRRset(name string, rtype dnsmessage.Type) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassANY}
}

// addRecord returns the change that adds one record at name.
func addRecord(name string, rtype dnsmessage.Type, ttl uint32, data []byte) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassINET, ttl: ttl, data: data}
}

// addressType is the record type that holds addr.
func addressType(addr netip.Addr) dnsmessage.Type {
	if addr.Is4() {
		return dnsmessage.TypeA
	}
	return dnsmessage.TypeAAAA
}

// forwardChanges returns the update section for the forward zone: drop
// whatever is at the name today, then put the lease there.
//
// The delete comes first and covers the whole RRset rather than one record,
// because a client that moved to a new address would otherwise end up with
// both, and a resolver would hand out the stale one half the time. RFC 2136
// applies the update section in order and as one transaction, so the two
// travel in a single message.
func forwardChanges(j job, ttl uint32) []change {
	rtype := addressType(j.addrs[0])
	changes := make([]change, 0, len(j.addrs)+1)
	changes = append(changes, deleteRRset(j.name, rtype))
	if j.remove {
		return changes
	}
	for _, addr := range j.addrs {
		changes = append(changes, addRecord(j.name, rtype, ttl, addr.AsSlice()))
	}
	return changes
}

// reverseChanges returns the update section for one address's reverse zone.
func reverseChanges(j job, addr netip.Addr, ttl uint32) ([]change, error) {
	owner := ptrName(addr)
	changes := []change{deleteRRset(owner, dnsmessage.TypePTR)}
	if j.remove {
		return changes, nil
	}
	target, err := packName(j.name)
	if err != nil {
		return nil, err
	}
	return append(changes, addRecord(owner, dnsmessage.TypePTR, ttl, target)), nil
}

// buildUpdate renders an RFC 2136 UPDATE message.
//
// The four sections carry different things from a query: the single question
// is the zone being updated, asked as an SOA so a server that does not
// implement UPDATE has something sensible to refuse; the answer section holds
// prerequisites, of which this plugin uses none; and the authority section
// holds the changes.
//
// Names are written out in full. Compression would save a few octets, and
// nsupdate does use it, but the TSIG record's owner name may not be
// compressed and a message whose names are all uncompressed is one where the
// bytes that were signed can be recovered from the bytes that arrived.
func buildUpdate(id uint16, zone string, changes []change) ([]byte, error) {
	u := updateBuilder{b: dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, OpCode: opCodeUpdate})}
	u.do(u.b.StartQuestions)
	u.do(func() error { return u.zone(zone) })
	u.do(u.b.StartAnswers)
	u.do(u.b.StartAuthorities)
	for _, c := range changes {
		u.do(func() error { return u.change(c) })
	}
	u.do(u.b.StartAdditionals)
	if u.err != nil {
		return nil, u.err
	}
	return u.b.Finish()
}

// updateBuilder wraps dnsmessage.Builder and keeps the first error, so a
// message is written as a sequence of calls rather than as a ladder of
// identical error checks. Every step after a failure is a no-op.
type updateBuilder struct {
	b   dnsmessage.Builder
	err error
}

// do runs one step unless an earlier one already failed.
func (u *updateBuilder) do(step func() error) {
	if u.err != nil {
		return
	}
	u.err = step()
}

// zone writes the single question that names the zone being updated.
func (u *updateBuilder) zone(zone string) error {
	name, err := dnsmessage.NewName(zone)
	if err != nil {
		return fmt.Errorf("zone %q: %w", zone, err)
	}
	return u.b.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeSOA,
		Class: dnsmessage.ClassINET,
	})
}

// change writes one record of the update section.
//
// Every record goes on the wire as an opaque resource. dnsmessage has typed
// bodies for A, AAAA and PTR, but none of them can hold the empty RDATA an
// RRset delete needs, and building the two forms the same way keeps one path
// through the encoder instead of two that have to agree.
func (u *updateBuilder) change(c change) error {
	name, err := dnsmessage.NewName(c.name)
	if err != nil {
		return fmt.Errorf("record name %q: %w", c.name, err)
	}
	return u.b.UnknownResource(
		dnsmessage.ResourceHeader{Name: name, Class: c.class, TTL: c.ttl},
		dnsmessage.UnknownResource{Type: c.rtype, Data: c.data},
	)
}

// randomID returns a message ID. It is the only thing an off-path attacker
// has to guess in order to have a forged answer looked at, so it comes from
// the cryptographic source rather than from math/rand.
func randomID() uint16 {
	var b [2]byte
	// crypto/rand.Read has not returned an error since Go 1.24: it panics
	// internally if the operating system's source fails.
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
