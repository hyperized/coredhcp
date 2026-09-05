// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ratelimit

import "time"

// Both fields are durations, not a token count, so refill is integer
// arithmetic on the clock; capacity/interval gives the token count.
type limit struct {
	interval time.Duration
	capacity time.Duration
}

// Only used for the startup log line.
func (l limit) tokens() int64 {
	return int64(l.capacity / l.interval)
}

// Reused once the table is full, so nothing here may be held onto across a fetch.
type bucket struct {
	prev, next *bucket

	// Kept so an eviction can find its map entry without walking the map.
	key string

	// Capped at the limit's capacity; one request costs one interval.
	credit time.Duration

	// Refill is lazy: a bucket nobody looks at costs nothing, so the plugin
	// needs no timer or goroutine.
	last time.Time

	// The summary window this bucket last counted a drop in - how the
	// distinct-client count is tracked without a second map an attacker could grow.
	gen uint64
}

func (b *bucket) allow(now time.Time, l limit) bool {
	elapsed := now.Sub(b.last)
	switch {
	case elapsed >= l.capacity:
		// Also where a bucket with unset last lands: Sub saturates at the
		// largest Duration, and adding it would overflow.
		b.credit = l.capacity
	case elapsed > 0:
		b.credit = min(b.credit+elapsed, l.capacity)
	}
	b.last = now
	if b.credit < l.interval {
		return false
	}
	b.credit -= l.interval
	return true
}

// Not safe for concurrent use; state owns one table and holds the mutex over
// every call.
type table struct {
	buckets map[string]*bucket
	head    *bucket
	tail    *bucket
	maxKeys int
}

// Not pre-sized to maxKeys: that bound is a safety ceiling usually far above
// the real client count, so pre-sizing to it would waste the memory the
// bound exists to protect.
func newTable(maxKeys int) *table {
	return &table{buckets: make(map[string]*bucket), maxKeys: maxKeys}
}

// key is only read, and copied only when a new entry needs a name, so the
// caller may pass a slice of a stack buffer.
func (t *table) fetch(key []byte, now time.Time, capacity time.Duration) *bucket {
	if b, ok := t.buckets[string(key)]; ok {
		t.touch(b)
		return b
	}
	b := t.reuseOrNew()
	b.key = string(key)
	b.credit = capacity
	b.last = now
	b.gen = 0
	t.buckets[b.key] = b
	t.pushFront(b)
	return b
}

func (t *table) reuseOrNew() *bucket {
	if len(t.buckets) < t.maxKeys {
		return &bucket{}
	}
	b := t.tail
	t.unlink(b)
	delete(t.buckets, b.key)
	return b
}

func (t *table) touch(b *bucket) {
	if b == t.head {
		return
	}
	t.unlink(b)
	t.pushFront(b)
}

func (t *table) unlink(b *bucket) {
	if b.prev != nil {
		b.prev.next = b.next
	} else {
		t.head = b.next
	}
	if b.next != nil {
		b.next.prev = b.prev
	} else {
		t.tail = b.prev
	}
	b.prev, b.next = nil, nil
}

func (t *table) pushFront(b *bucket) {
	b.prev = nil
	b.next = t.head
	if t.head != nil {
		t.head.prev = b
	}
	t.head = b
	if t.tail == nil {
		t.tail = b
	}
}
