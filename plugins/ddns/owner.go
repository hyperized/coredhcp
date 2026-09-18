// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"bytes"
	"container/list"
	"net/netip"
	"slices"
	"sync"
)

// maxOwners is how many names one instance remembers having written. At a
// few hundred octets per entry that is a couple of megabytes at worst, and
// well past the number of clients a segment this plugin sits on holds.
const maxOwners = 8192

// owners is the register of names this instance wrote, and who it wrote
// them for.
//
// A DHCPRELEASE carries no proof of anything: whoever is on the segment can
// send one naming any address and any host name, and the server answers
// nothing back. The DHCID prerequisite on the delete is what stops such a
// message from taking a name out of the zone, but it costs a round trip to
// find that out, and it only covers names that carry a DHCID at all. This
// register is the gate in front of it: unless this process itself wrote that
// name, for that client, at those addresses, the release is dropped on the
// packet path and no message is sent.
//
// It lives in memory and does not survive a restart, which is deliberate.
// After a restart a release is ignored until the client renews and the name
// is written again, so a record a client has given up can stand for up to
// one lease time. The alternative is trusting a file on disk to decide who
// may delete a name, and a record that lingers is the cheaper mistake.
//
// The register is bounded and drops the name whose registration is oldest
// once it is full. A client that has been pushed out is in the same position
// as one that registered before a restart.
//
// It is safe for concurrent use: handlers on several listener goroutines
// read it while the worker writes.
type owners struct {
	mu     sync.Mutex
	max    int
	byName map[string]registration
	order  *list.List // names, least recently written at the front
}

// registration is one name this instance wrote.
type registration struct {
	dhcid []byte
	addrs []netip.Addr
	at    *list.Element
}

// newOwners returns an empty register holding at most limit names.
func newOwners(limit int) *owners {
	return &owners{max: limit, byName: make(map[string]registration), order: list.New()}
}

// record notes that name now holds addrs for the client dhcid identifies.
// The caller's slices are copied: they come off the packet path and are not
// this register's to hold on to.
func (o *owners) record(name string, dhcid []byte, addrs []netip.Addr) {
	o.mu.Lock()
	defer o.mu.Unlock()
	reg := registration{dhcid: bytes.Clone(dhcid), addrs: slices.Clone(addrs)}
	if old, ok := o.byName[name]; ok {
		reg.at = old.at
		o.order.MoveToBack(reg.at)
	} else {
		reg.at = o.order.PushBack(name)
	}
	o.byName[name] = reg
	o.evict()
}

// evict drops the oldest registrations until the register is inside its
// bound. It runs under the caller's lock.
func (o *owners) evict() {
	for o.order.Len() > o.max {
		el := o.order.Front()
		o.order.Remove(el)
		delete(o.byName, nameOf(el))
	}
}

// nameOf reads the name back out of a list element. The list only ever holds
// the strings record put there, so the assertion cannot fail; discarding the
// second result keeps it from reading as a conversion nobody checked.
func nameOf(el *list.Element) string {
	name, _ := el.Value.(string)
	return name
}

// holds reports whether this instance wrote name for the client dhcid
// identifies, at every one of addrs.
//
// Every address has to match. A release naming an address this server never
// wrote comes either from a client that has lost track or from one that is
// guessing, and neither is a reason to take a name out of the zone.
func (o *owners) holds(name string, dhcid []byte, addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	reg, ok := o.byName[name]
	if !ok || !bytes.Equal(reg.dhcid, dhcid) {
		return false
	}
	for _, addr := range addrs {
		if !slices.Contains(reg.addrs, addr) {
			return false
		}
	}
	return true
}

// forget drops a name's registration, once its records are out of the zone.
func (o *owners) forget(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	reg, ok := o.byName[name]
	if !ok {
		return
	}
	o.order.Remove(reg.at)
	delete(o.byName, name)
}
