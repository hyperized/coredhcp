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
// few hundred octets per entry that is a couple of megabytes at worst.
const maxOwners = 8192

// owners is the register of names this instance wrote, and who it wrote
// them for. A DHCPRELEASE carries no proof of anything, so a release that
// this register does not recognise is dropped on the packet path rather than
// costing a round trip to have the name server refuse it.
//
// It is deliberately in memory only, and bounded. A name it has forgotten,
// after a restart or an eviction, leaves a record standing until the client
// renews: a record that lingers is a cheaper mistake than trusting a file on
// disk to decide who may delete a name.
//
// Safe for concurrent use: handlers on several listener goroutines read it
// while the worker writes.
type owners struct {
	mu     sync.Mutex
	max    int
	byName map[string]registration
	order  *list.List // names, least recently written at the front
}

type registration struct {
	dhcid []byte
	addrs []netip.Addr
	at    *list.Element
}

func newOwners(limit int) *owners {
	return &owners{max: limit, byName: make(map[string]registration), order: list.New()}
}

// record notes that name now holds addrs for the client dhcid identifies.
// The slices are copied because they come off the packet path.
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

// evict runs under the caller's lock.
func (o *owners) evict() {
	for o.order.Len() > o.max {
		el := o.order.Front()
		o.order.Remove(el)
		delete(o.byName, nameOf(el))
	}
}

// nameOf reads the name back out of a list element. The list only ever holds
// the strings record put there, so the assertion cannot fail.
func nameOf(el *list.Element) string {
	name, _ := el.Value.(string)
	return name
}

// holds reports whether this instance wrote name for the client dhcid
// identifies, at every one of addrs. Every address has to match: a release
// naming an address this server never wrote is no reason to take a name out
// of the zone.
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
