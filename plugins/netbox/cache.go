// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// maxCacheEntries bounds how many MAC addresses the plugin remembers. A DHCP
// server sees a bounded population of clients, so this is high enough that a
// normal segment never evicts, and low enough that a scan of spoofed source
// addresses cannot grow the map without limit.
const maxCacheEntries = 4096

// lookupResult is what NetBox knows about one MAC address.
//
// found reports whether the MAC is assigned to a device or VM interface at
// all. A found MAC whose interface carries no active address of a family
// leaves that family's prefix zero, which is a real answer and cached as one:
// the operator documented the interface but not that address.
type lookupResult struct {
	v4    netip.Prefix
	v6    netip.Prefix
	found bool
}

// record keeps p as the answer for its family unless one is already set.
// NetBox returns addresses in its own order and we take the first of each
// family, so an interface with several addresses answers consistently.
func (r *lookupResult) record(p netip.Prefix) {
	if p.Addr().Is4() {
		if !r.v4.IsValid() {
			r.v4 = p
		}
		return
	}
	if !r.v6.IsValid() {
		r.v6 = p
	}
}

// cacheEntry is one MAC address' answer and the instant it goes stale. The key
// is kept alongside the value so eviction can delete the map entry from the
// list element alone.
type cacheEntry struct {
	key     string
	result  lookupResult
	expires time.Time
}

// cache is a bounded LRU of lookup results with per-entry expiry.
//
// It is safe for concurrent use. Expired entries are dropped when they are
// next read rather than by a background goroutine: an entry nobody asks for
// costs nothing but a map slot, and the bound already caps that.
type cache struct {
	mu      sync.Mutex
	max     int
	order   *list.List // *cacheEntry, most recently used at the front
	entries map[string]*list.Element
}

// newCache returns an empty cache holding at most limit entries. A limit below
// one is raised to one, so a caller cannot build a cache that evicts what it
// just stored.
func newCache(limit int) *cache {
	if limit < 1 {
		limit = 1
	}
	return &cache{
		max:     limit,
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

// get returns the cached result for key if it is present and still valid at
// now. An expired entry is dropped and reported as a miss.
func (c *cache) get(key string, now time.Time) (lookupResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {
		return lookupResult{}, false
	}
	ent := el.Value.(*cacheEntry)
	if !now.Before(ent.expires) {
		c.drop(el)
		return lookupResult{}, false
	}
	c.order.MoveToFront(el)
	return ent.result, true
}

// put stores result under key until expires, evicting the least recently used
// entry when the cache is full.
func (c *cache) put(key string, result lookupResult, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {
		ent := el.Value.(*cacheEntry)
		ent.result = result
		ent.expires = expires
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.max {
		// max is at least one, so a full list always has a back element.
		c.drop(c.order.Back())
	}
	c.entries[key] = c.order.PushFront(&cacheEntry{key: key, result: result, expires: expires})
}

// drop removes el from both the list and the map. The caller must hold c.mu.
func (c *cache) drop(el *list.Element) {
	delete(c.entries, el.Value.(*cacheEntry).key)
	c.order.Remove(el)
}

// len reports how many entries the cache currently holds, expired ones
// included.
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
