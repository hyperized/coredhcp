// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ratelimit

import "time"

// limit is a rate in the form the bucket arithmetic wants it: the time one
// token takes to accrue, and the credit a full bucket holds. Both are
// durations, so a refill is integer arithmetic on the clock and a bucket
// holding capacity credit is a bucket holding capacity/interval tokens.
type limit struct {
	interval time.Duration
	capacity time.Duration
}

// tokens is how many requests a full bucket under this limit pays for. It is
// only used for the line logged at startup.
func (l limit) tokens() int64 {
	return int64(l.capacity / l.interval)
}

// bucket is one client's token bucket together with its place in the LRU
// list. Buckets are reused when the table is full, so nothing here may be
// held on to across a fetch.
type bucket struct {
	prev, next *bucket

	// key is the identifier this bucket was filed under, kept so an eviction
	// can find its map entry without walking the map.
	key string

	// credit is banked time, capped at the limit's capacity. One request
	// costs one interval.
	credit time.Duration

	// last is when credit was brought up to date. Refill is lazy: a bucket
	// nobody looks at costs nothing, which is why the plugin needs no timer
	// and starts no goroutine.
	last time.Time

	// gen is the summary window this bucket was last counted a drop in. It
	// is how the distinct-client count in the summary is kept without a
	// second map that an attacker could grow.
	gen uint64
}

// allow brings the bucket up to date at now and charges it one request,
// reporting whether it could pay.
func (b *bucket) allow(now time.Time, l limit) bool {
	elapsed := now.Sub(b.last)
	switch {
	case elapsed >= l.capacity:
		// Also the branch a bucket with an unset last would take, where Sub
		// saturates at the largest Duration and adding it would overflow.
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

// table is a fixed-capacity LRU of buckets: a map for lookup, and an
// intrusive doubly linked list for recency with the most recently seen
// bucket at the head.
//
// It is not safe for concurrent use. state owns one and holds its mutex over
// every call.
//
// Once the table is full, each new key reuses the bucket it evicts, so a
// flood of one-shot keys allocates the key string and nothing else.
type table struct {
	buckets map[string]*bucket
	head    *bucket
	tail    *bucket
	maxKeys int
}

// newTable returns an empty table that will hold at most maxKeys buckets.
//
// The map is not pre-sized to maxKeys. That number is an upper bound an
// operator sets for safety and is usually far above the number of clients
// that ever turn up, so reserving 65536 buckets on a segment with twelve of
// them would waste the memory the bound was meant to protect.
func newTable(maxKeys int) *table {
	return &table{buckets: make(map[string]*bucket), maxKeys: maxKeys}
}

// fetch returns key's bucket, creating a full one if the key is new and
// evicting the least recently seen bucket to make room when the table is
// already at its bound.
//
// key is only read, and its bytes are copied when a new entry needs a name,
// so the caller may pass a slice of a stack buffer.
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

// reuseOrNew hands back a bucket to file a new key under, evicting the tail
// of the list once the table is at its bound.
func (t *table) reuseOrNew() *bucket {
	if len(t.buckets) < t.maxKeys {
		return &bucket{}
	}
	b := t.tail
	t.unlink(b)
	delete(t.buckets, b.key)
	return b
}

// touch moves b to the head of the list, marking it most recently seen.
func (t *table) touch(b *bucket) {
	if b == t.head {
		return
	}
	t.unlink(b)
	t.pushFront(b)
}

// unlink takes b out of the list and leaves the map alone.
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

// pushFront puts b at the head of the list.
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
