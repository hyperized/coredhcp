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

const (
	// opCodeUpdate is the UPDATE opcode of RFC 2136. It reuses the header of
	// a query with different meanings for the four section counts: zone,
	// prerequisite, update and additional.
	opCodeUpdate = dnsmessage.OpCode(5)

	// classNone is the NONE class RFC 2136 uses for two things: in the
	// prerequisite section it says an RRset must not exist, and in the
	// update section it deletes one named record out of an RRset.
	// dnsmessage has no constant for it.
	classNone = dnsmessage.Class(254)
)

// change is one record of a prerequisite or an update section. Both are
// written the same way and the class says which meaning applies: in an
// update, IN adds, ANY with no RDATA and a TTL of zero deletes the whole
// RRset (RFC 2136 section 2.5.2) and NONE with RDATA deletes that one record
// (2.5.4); in a prerequisite, NONE with no RDATA requires the RRset to be
// absent (2.4.3) and IN with RDATA requires it to be exactly what is given
// (2.4.2).
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

// deleteRecord returns the change that removes one record from an RRset.
func deleteRecord(name string, rtype dnsmessage.Type, data []byte) change {
	return change{name: name, rtype: rtype, class: classNone, data: data}
}

// addRecord returns the change that adds one record at name.
func addRecord(name string, rtype dnsmessage.Type, ttl uint32, data []byte) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassINET, ttl: ttl, data: data}
}

// noRRset returns the prerequisite that no record of rtype exists at name.
func noRRset(name string, rtype dnsmessage.Type) change {
	return change{name: name, rtype: rtype, class: classNone}
}

// rrsetEquals returns the prerequisite that the RRset of rtype at name is
// exactly the one record data holds. The name server does the comparing, so
// a name held by another client fails there rather than in a read that a
// second message then races.
func rrsetEquals(name string, rtype dnsmessage.Type, data []byte) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassINET, data: data}
}

// freshPrereqs is what a first claim on a name asks for: that no DHCID is
// there yet. A name with no DHCID is unclaimed and RFC 4703 section 5.3.1
// has the server hand it over, which covers records an operator wrote by
// hand; protect: is how one is kept out of reach of that.
func freshPrereqs(j job) []change {
	return []change{noRRset(j.name, typeDHCID)}
}

// ownedPrereqs is what the second attempt asks for, and what every
// withdrawal asks for: that the DHCID at the name is the one this client's
// identity produces (RFC 4703 sections 5.3.2 and 5.5).
func ownedPrereqs(j job) []change {
	return []change{rrsetEquals(j.name, typeDHCID, j.dhcid)}
}

// addressType is the record type that holds addr.
func addressType(addr netip.Addr) dnsmessage.Type {
	if addr.Is4() {
		return dnsmessage.TypeA
	}
	return dnsmessage.TypeAAAA
}

// forwardChanges returns the update section that claims a name.
//
// The delete comes first and covers the whole RRset rather than one record,
// because a client that moved to a new address would otherwise end up with
// both, and a resolver would hand out the stale one half the time. RFC 2136
// applies the update section in order and as one transaction, so all of it
// travels in a single message.
func forwardChanges(j job, ttl uint32) []change {
	rtype := addressType(j.addrs[0])
	changes := make([]change, 0, len(j.addrs)+2)
	changes = append(changes, deleteRRset(j.name, rtype))
	for _, addr := range j.addrs {
		changes = append(changes, addRecord(j.name, rtype, ttl, addr.AsSlice()))
	}
	return append(changes, addRecord(j.name, typeDHCID, ttl, j.dhcid))
}

// withdrawChanges returns the update section that takes a name back out of
// the zone.
//
// The DHCID goes as a single-record delete rather than an RRset delete: the
// prerequisite has already held the server to our own record, and deleting
// exactly that one leaves anything else at the name alone.
func withdrawChanges(j job) []change {
	return []change{
		deleteRRset(j.name, addressType(j.addrs[0])),
		deleteRecord(j.name, typeDHCID, j.dhcid),
	}
}

// reverseChanges returns the update section for one address's reverse zone.
func reverseChanges(j job, addr netip.Addr, ttl uint32) ([]change, error) {
	owner := ptrName(addr)
	changes := make([]change, 0, 2)
	changes = append(changes, deleteRRset(owner, dnsmessage.TypePTR))
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
// the prerequisites the server has to find true before it applies anything;
// and the authority section holds the changes.
//
// Names are written out in full. Compression would save a few octets, and
// nsupdate does use it, but the TSIG record's owner name may not be
// compressed and a message whose names are all uncompressed is one where the
// bytes that were signed can be recovered from the bytes that arrived.
func buildUpdate(id uint16, zone string, prereqs, changes []change) ([]byte, error) {
	u := updateBuilder{b: dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, OpCode: opCodeUpdate})}
	u.do(u.b.StartQuestions)
	u.do(func() error { return u.zone(zone) })
	u.do(u.b.StartAnswers)
	for _, c := range prereqs {
		u.do(func() error { return u.record(c) })
	}
	u.do(u.b.StartAuthorities)
	for _, c := range changes {
		u.do(func() error { return u.record(c) })
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

// record writes one record into whichever section is open.
//
// Every record goes on the wire as an opaque resource. dnsmessage has typed
// bodies for A, AAAA and PTR, but none of them can hold the empty RDATA an
// RRset delete needs, it has no body for DHCID at all, and building every
// form the same way keeps one path through the encoder instead of several
// that have to agree.
func (u *updateBuilder) record(c change) error {
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
