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

// RFC 2136's UPDATE opcode reuses a query's header with different meanings
// for the four section counts: zone, prerequisite, update and additional.
const opCodeUpdate = dnsmessage.OpCode(5)

// Class says what to do with it: IN adds the record; ANY with no RDATA and
// a zero TTL is RFC 2136 section 2.5.2's "Delete an RRset" form.
type change struct {
	name  string
	rtype dnsmessage.Type
	class dnsmessage.Class
	ttl   uint32
	data  []byte
}

func deleteRRset(name string, rtype dnsmessage.Type) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassANY}
}

func addRecord(name string, rtype dnsmessage.Type, ttl uint32, data []byte) change {
	return change{name: name, rtype: rtype, class: dnsmessage.ClassINET, ttl: ttl, data: data}
}

func addressType(addr netip.Addr) dnsmessage.Type {
	if addr.Is4() {
		return dnsmessage.TypeA
	}
	return dnsmessage.TypeAAAA
}

// Deletes the whole RRset before adding the lease, in one RFC 2136
// transaction, so a client moving address never ends up with both records.
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

// Zone is asked as SOA, so a server without UPDATE support refuses sensibly.
// Names are uncompressed throughout, since TSIG's owner name must not be.
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

// Keeps the first error, so a message is written as a sequence of calls
// rather than a ladder of identical error checks.
type updateBuilder struct {
	b   dnsmessage.Builder
	err error
}

func (u *updateBuilder) do(step func() error) {
	if u.err != nil {
		return
	}
	u.err = step()
}

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

// Written as an opaque resource, not a typed A/AAAA/PTR body: none of those
// can hold the empty RDATA an RRset delete needs.
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

// The message ID is the only thing an off-path attacker must guess to get a
// forged answer looked at, so it comes from crypto/rand, not math/rand.
func randomID() uint16 {
	var b [2]byte
	// crypto/rand.Read panics rather than returning an error since Go 1.24.
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
