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

// High enough that a normal segment never evicts, low enough that a scan of
// spoofed source addresses cannot grow the map without limit.
const maxCacheEntries = 4096

// found says the MAC is assigned to an interface at all. A found MAC whose
// interface carries no active address of a family leaves that prefix zero,
// which is a real answer and is cached as one.
type lookupResult struct {
	v4    netip.Prefix
	v6    netip.Prefix
	found bool
}

// First of each family wins, in the order NetBox returns them, so an interface
// with several addresses answers consistently.
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

// The key is kept alongside the value so eviction can delete the map entry
// from the list element alone.
type cacheEntry struct {
	key     string
	result  lookupResult
	expires time.Time
}

// Safe for concurrent use. Expired entries are dropped when next read rather
// than by a goroutine: an entry nobody asks for costs one map slot, which the
// bound already caps.
type cache struct {
	mu      sync.Mutex
	max     int
	order   *list.List // *cacheEntry, most recently used at the front
	entries map[string]*list.Element
}

// A limit below one is raised to one, so a caller cannot build a cache that
// evicts what it just stored.
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

// An expired entry is dropped and reported as a miss.
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

// The caller must hold c.mu.
func (c *cache) drop(el *list.Element) {
	delete(c.entries, el.Value.(*cacheEntry).key)
	c.order.Remove(el)
}

// Counts expired entries that have not been read since.
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
