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

// dropWarnInterval is how often a full queue is complained about. A DNS
// server that has stopped answering makes every packet drop an update, and a
// line per packet would bury everything else in the log.
const dropWarnInterval = time.Minute

// job is one client's records, as the handler saw them.
//
// All of a job's addresses belong to one family and one name, which is what
// lets the forward update delete the RRset once and then add every address
// back in the same message. Splitting them into a job each would have the
// second delete undo the first.
type job struct {
	name   string
	addrs  []netip.Addr
	remove bool
}

// counters record what the worker has been doing. They are read through the
// log rather than exported: coredhcp's Prometheus surface belongs to the
// metrics plugin, and a plugin that registers collectors of its own would
// conflict with a second copy of itself in the other family's chain.
type counters struct {
	sent      atomic.Uint64
	dropped   atomic.Uint64
	truncated atomic.Uint64
	refused   atomic.Uint64
	failed    atomic.Uint64
}

// dropLog rate limits the warning about a full queue.
type dropLog struct {
	mu   sync.Mutex
	last time.Time
}

// enqueue hands a job to the worker, dropping it when the queue is full.
//
// This runs on the packet path, so it never blocks. A full queue means the
// DNS server is answering more slowly than clients are arriving, and a lease
// that is handed out a second late is worse than a DNS record that is a
// minute stale.
func (p *pluginState) enqueue(j job) {
	select {
	case p.queue <- j:
	default:
		p.dropped(j)
	}
}

// dropped counts a dropped job and complains about it, at most once per
// dropWarnInterval.
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

// run is the worker. One goroutine owns the exchange with the DNS server, so
// updates for the same name reach it in the order the handlers queued them.
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

// start launches the worker.
func (p *pluginState) start() {
	go p.run()
}

// stopWorker shuts the worker down and waits for it to finish the job it is
// on. Whatever is still queued is abandoned.
//
// Nothing calls this in production: the server has no way to unload a plugin,
// and the process exiting is the shutdown. It is here so tests reap the
// goroutine instead of leaking one each.
func (p *pluginState) stopWorker() {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

// apply sends the messages one job turns into: one to the forward zone, and
// one to the reverse zone of every address that falls inside a configured
// reverse: network.
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

// reverseZoneFor returns the configured reverse zone that holds addr. The
// first matching network wins, so a more specific network listed first
// overrides a wider one after it.
func (p *pluginState) reverseZoneFor(addr netip.Addr) (string, bool) {
	for _, r := range p.reverse {
		if r.prefix.Contains(addr) {
			return r.zone, true
		}
	}
	return "", false
}

// sendUpdate sends one message and counts what came back. Nothing here can
// fail in a way the caller could act on: the lease was handed out before the
// job was queued, so a failed update is a log line and a counter.
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

// update builds, signs and sends one message, and checks the answer.
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
