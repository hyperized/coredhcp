// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"context"
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
//
// dhcid is worked out on the packet path, where the request still is, and
// carried along because the worker needs it both as the record to write and
// as the prerequisite to write it under.
type job struct {
	name   string
	addrs  []netip.Addr
	dhcid  []byte
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
	conflicts atomic.Uint64
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
	log.Warningf("the update queue is full, %d update(s) dropped so far, most recently for %s; raise %s<n> or find out why %s is slow to answer",
		total, j.name, queueArg, p.server)
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
			p.apply(p.ctx, j)
		}
	}
}

// start launches the worker.
func (p *pluginState) start() {
	go p.run()
}

// stopWorker shuts the worker down and waits for it to finish the job it is
// on. Whatever is still queued is abandoned, and an exchange that is in
// flight is cut short by the cancelled context rather than running out its
// own timeout.
//
// Nothing calls this in production: the server has no way to unload a plugin,
// and the process exiting is the shutdown. It is here so tests reap the
// goroutine instead of leaking one each.
func (p *pluginState) stopWorker() {
	p.stopOnce.Do(func() {
		close(p.stop)
		p.cancel()
	})
	<-p.done
}

// apply sends the messages one job turns into: one to the forward zone, and
// then, only if the server took that one, one to the reverse zone of every
// address that falls inside a configured reverse: network.
//
// The reverse zone waits on the forward one because a PTR pointing at a name
// the client does not hold is the same takeover by another route.
func (p *pluginState) apply(ctx context.Context, j job) {
	if !p.sendForward(ctx, j) {
		return
	}
	p.sendReverse(ctx, j)
}

// sendForward reports whether the name server did as it was asked.
func (p *pluginState) sendForward(ctx context.Context, j job) bool {
	err := p.forwardExchange(ctx, j)
	if prereqFailed(err) {
		p.stats.conflicts.Add(1)
		log.Warningf("%s is held by another client, so the record was left as it was (%v); add it to %s<name> or give this client a different hostname",
			j.name, err, protectArg)
		return false
	}
	p.tally(p.zone, err)
	if err != nil {
		return false
	}
	p.remember(j)
	return true
}

// forwardExchange is the conflict resolution of RFC 4703 section 5.3, which
// settles a name two clients both want without letting the second overwrite
// the first: the claim asks that nothing hold the name yet, and if something
// does, asks again that what holds it be this client's own DHCID. A name
// held by another client fails both and is left exactly as it was.
//
// A withdrawal only ever asks the second question.
func (p *pluginState) forwardExchange(ctx context.Context, j job) error {
	if j.remove {
		return p.update(ctx, p.zone, ownedPrereqs(j), withdrawChanges(j))
	}
	err := p.update(ctx, p.zone, freshPrereqs(j), forwardChanges(j, p.ttl))
	if !prereqFailed(err) {
		return err
	}
	log.Debugf("%s is already claimed, asking again as the client that claimed it", j.name)
	return p.update(ctx, p.zone, ownedPrereqs(j), forwardChanges(j, p.ttl))
}

// remember keeps or drops the note a later release is checked against.
func (p *pluginState) remember(j job) {
	if j.remove {
		p.owners.forget(j.name)
		return
	}
	p.owners.record(j.name, j.dhcid, j.addrs)
}

// sendReverse replaces the PTR of every address that falls inside a
// configured reverse: network. These messages carry no prerequisites: the
// zone is named after an address the server handed out itself, so there is
// nothing there for a client to claim.
func (p *pluginState) sendReverse(ctx context.Context, j job) {
	for _, addr := range j.addrs {
		zone, ok := p.reverseZoneFor(addr)
		if !ok {
			continue
		}
		changes, err := reverseChanges(j, addr, p.ttl)
		if err != nil {
			log.Warningf("no PTR was written in %s: %v; check the %s<cidr> network and the name the client asked for", zone, err, reverseArg)
			continue
		}
		p.tally(zone, p.update(ctx, zone, nil, changes))
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

// tally counts what one message came back with and says so in the log.
// Nothing here can fail in a way a caller could act on: the lease was handed
// out before the job was queued, so a failed update is a log line and a
// counter.
func (p *pluginState) tally(zone string, err error) {
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
	log.Warningf("updating %s at %s failed: %v; check the zone's update ACL on that server and that it accepts TSIG key %s",
		zone, p.server, err, p.key.name)
}

// update builds, signs and sends one message, and checks the answer.
func (p *pluginState) update(ctx context.Context, zone string, prereqs, changes []change) error {
	id := randomID()
	msg, err := buildUpdate(id, zone, prereqs, changes)
	if err != nil {
		return err
	}
	signed, mac := p.key.sign(msg, p.timeNow(), id)
	resp, err := p.exchange(ctx, signed)
	if err != nil {
		return err
	}
	return p.checkResponse(resp, mac, id)
}
