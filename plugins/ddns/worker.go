// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// A stalled DNS server makes every packet drop an update; one line per
// packet would bury everything else in the log.
const dropWarnInterval = time.Minute

// All of one job's addresses share a family and name, so the forward update
// can delete the RRset once and add every address back in the same message.
type job struct {
	name   string
	addrs  []netip.Addr
	remove bool
}

// Read through the log rather than exported: coredhcp's Prometheus surface
// belongs to the metrics plugin, not to a second collector per family's chain.
type counters struct {
	sent      atomic.Uint64
	dropped   atomic.Uint64
	truncated atomic.Uint64
	refused   atomic.Uint64
	failed    atomic.Uint64
}

type dropLog struct {
	mu   sync.Mutex
	last time.Time
}

// Runs on the packet path, so it never blocks: a lease handed out a second
// late is worse than a DNS record that is a minute stale.
func (p *pluginState) enqueue(j job) {
	select {
	case p.queue <- j:
	default:
		p.dropped(j)
	}
}

func (p *pluginState) dropped(j job) {
	total := p.stats.dropped.Add(1)
	p.drops.mu.Lock()
	defer p.drops.mu.Unlock()
	now := p.timeNow()
	if now.Sub(p.drops.last) < dropWarnInterval {
		return
	}
	p.drops.last = now
	log.Warningf("the update queue is full, %d update(s) dropped so far, most recently for %s", total, j.name)
}

// One goroutine owns the exchange, so updates for the same name arrive in
// the order the handlers queued them.
func (p *pluginState) run() {
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case j := <-p.queue:
			p.apply(j)
		}
	}
}

func (p *pluginState) start() {
	go p.run()
}

// Nothing calls this in production: the server has no way to unload a
// plugin. It exists so tests can reap the goroutine instead of leaking one.
func (p *pluginState) stopWorker() {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

func (p *pluginState) apply(j job) {
	p.sendUpdate(p.zone, forwardChanges(j, p.ttl))
	for _, addr := range j.addrs {
		zone, ok := p.reverseZoneFor(addr)
		if !ok {
			continue
		}
		changes, err := reverseChanges(j, addr, p.ttl)
		if err != nil {
			log.Warningf("%s: %v", zone, err)
			continue
		}
		p.sendUpdate(zone, changes)
	}
}

// First matching network wins, so listing a more specific one first
// overrides a wider one after it.
func (p *pluginState) reverseZoneFor(addr netip.Addr) (string, bool) {
	for _, r := range p.reverse {
		if r.prefix.Contains(addr) {
			return r.zone, true
		}
	}
	return "", false
}

// The lease was already handed out before the job was queued, so a failed
// update here is only a log line and a counter, nothing the caller can act on.
func (p *pluginState) sendUpdate(zone string, changes []change) {
	err := p.update(zone, changes)
	switch {
	case err == nil:
		p.stats.sent.Add(1)
		log.Debugf("updated %s", zone)
		return
	case errors.Is(err, ErrTruncated):
		p.stats.truncated.Add(1)
	case errors.Is(err, ErrRCode):
		p.stats.refused.Add(1)
	default:
		p.stats.failed.Add(1)
	}
	log.Warningf("updating %s failed: %v", zone, err)
}

func (p *pluginState) update(zone string, changes []change) error {
	id := randomID()
	msg, err := buildUpdate(id, zone, changes)
	if err != nil {
		return err
	}
	signed, mac := p.key.sign(msg, p.timeNow(), id)
	resp, err := p.exchange(signed)
	if err != nil {
		return err
	}
	return p.checkResponse(resp, mac, id)
}
