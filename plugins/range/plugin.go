// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package rangeplugin implements a plugin that hands out DHCPv4 leases
// from an address range, persisting them in a sqlite database.
//
// Configure it with the lease database, the first and last address of the
// pool, and the lease time:
//
//	server4:
//	  plugins:
//	    - range: leases.sqlite3 10.0.0.100 10.0.0.200 1h
//
// Four optional arguments may follow, in any order:
//
//	sweep:<duration>              how often expired leases are reclaimed in
//	                              the background. Defaults to half the lease
//	                              time, floored at 30s.
//	decline-probation:<duration>  how long an address a client declined is
//	                              held back from the pool. Defaults to 24h,
//	                              the same as Kea. 0 hands a declined address
//	                              straight back out.
//	decline-max:<count>           how many declined addresses may be held
//	                              back at the same time. Defaults to a tenth
//	                              of the pool, held between 1 and 65536.
//	                              0 disables the quarantine, the same as
//	                              decline-probation:0 does.
//	max-leases:<count>            how many leases this instance may hold at
//	                              once. Defaults to 65536. A pool with room
//	                              for more addresses than that needs this
//	                              raised, or it stops handing out leases at
//	                              the bound. 0 turns the bound off.
//
// Leases are reclaimed in two places: a background sweeper on a ticker, and
// lazily on the allocation path when the pool looks exhausted. Without either,
// expired leases pile up in the map, the allocator and the database forever,
// and a stable population of churning clients eventually exhausts the pool
// permanently (upstream issues #148 and #182).
//
// # RELEASE and DECLINE
//
// A DHCPRELEASE frees a lease only when the sender holds one and names it in
// ciaddr, which is how RFC 2131 §4.4.6 has a client identify the lease it is
// giving up. The message is never acknowledged and its chaddr is trivially
// forged, so a server that goes by the MAC alone can have its pool emptied by
// anyone on the segment: twenty forged releases drained an eleven-address
// pool, and a release from a MAC with no lease used to allocate one.
//
// A DHCPDECLINE means the client found the address already in use on the link.
// The lease goes away, but the address stays out of the pool for the probation
// period so the next client does not walk into the same conflict. Probation is
// tracked in memory only: a restart puts every declined address back into
// circulation.
//
// The quarantine is bounded, because a decline is as unauthenticated as a
// release. Nothing stops one host on the segment taking an offer and declining
// it, two packets per address, until the whole pool sits in probation and
// nobody gets a lease for the next day. At most decline-max addresses are held
// back at a time: past that, a declined address goes straight back to the
// pool, and a pool that runs dry ends the probation of whichever address has
// been held longest. Probation says which addresses look risky, it never
// reserves one.
//
// # Storage
//
// The reply to a client waits until its lease has reached the lease
// database, and a lease that cannot be written is refused rather than handed
// out: an address nobody can see after a restart is how two clients end up
// with the same one. Writes are queued to one writer goroutine, so a slow
// disk costs queue depth rather than blocking every other client, the
// sweeper and the lease API behind one insert.
package rangeplugin

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

var log = logger.GetLogger("plugins/range")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "range",
	Setup4: setupRange,
}

// newIPv4Allocator is bitmap.NewIPv4Allocator, extracted as a seam for
// tests. setupRange already validates that start <= end and that both
// parse as IPv4 addresses before calling this, so through the public API
// the allocator can never actually fail to construct; overriding this var
// is the only way to exercise that error path deterministically.
var newIPv4Allocator = bitmap.NewIPv4Allocator

const (
	// sweepArg names the optional argument that overrides the background
	// sweep interval, e.g. "sweep:5m".
	sweepArg = "sweep"

	// declineArg names the optional argument that overrides how long a
	// declined address stays out of the pool, e.g. "decline-probation:1h".
	declineArg = "decline-probation"

	// declineMaxArg names the optional argument that overrides how many
	// declined addresses may sit in quarantine at once, e.g. "decline-max:8".
	declineMaxArg = "decline-max"

	// maxLeasesArg names the optional argument that overrides how many
	// leases this instance may hold at once, e.g. "max-leases:4096".
	maxLeasesArg = "max-leases"

	// optionSyntax spells the optional arguments out for error messages.
	optionSyntax = sweepArg + ":<duration>, " + declineArg + ":<duration>, " + declineMaxArg + ":<count> or " + maxLeasesArg + ":<count>"

	// minSweepInterval floors the derived sweep interval. A short lease time
	// (a captive portal handing out 30s leases, say) must not turn the
	// sweeper into a hot loop taking the plugin lock.
	minSweepInterval = 30 * time.Second

	// defaultDeclineProbation is what Kea uses for decline-probation-period.
	// A day is long enough that whatever was squatting on the address has
	// usually gone, and short enough that one bad afternoon does not bleed a
	// pool dry.
	defaultDeclineProbation = 24 * time.Hour

	// declineQuarantineShare is the fraction of the pool decline-max defaults
	// to. A tenth covers the conflicts a segment produces for real, a printer
	// holding a static address inside the pool or a second DHCP server, and
	// leaves the rest of the pool to the clients that behave.
	declineQuarantineShare = 10

	// maxDeclineQuarantine caps that default however large the pool is. Each
	// quarantined address is a live map entry, and a segment producing tens of
	// thousands of genuine conflicts has a problem no probation period is
	// going to fix. An operator who wants more can still say so with
	// decline-max.
	maxDeclineQuarantine = 1 << 16

	// defaultMaxLeases bounds the lease table when max-leases says nothing.
	// Every lease is a map entry and a database row, so a pool wider than the
	// machine has memory for needs a bound that is not the pool.
	defaultMaxLeases = 1 << 16

	// leaseLimitEvery paces the refusal log. Once the table is full every
	// new client is turned away, and one line per packet would bury the
	// reason among the symptoms.
	leaseLimitEvery = time.Minute

	// maxHostnameLen is the RFC 1035 section 2.3.4 limit on a domain name,
	// and the length a client-supplied name is truncated to before it is
	// stored.
	maxHostnameLen = 255

	// hostnameChars is the allow-list a client-supplied name is filtered
	// through. The name is only ever shown to an operator, so anything that
	// is not a domain character is dropped rather than escaped later.
	hostnameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
)

// Record holds an IP lease record
type Record struct {
	IP net.IP

	// expires is the Unix second the lease lapses at. It is int64 and not
	// int because the 32-bit builds this runs on (a Raspberry Pi Zero is a
	// deployment target) would wrap it negative on 2038-01-19, at which
	// point every lease reads as expired and the pool empties itself.
	expires  int64
	hostname string
}

// expired reports whether the lease had already lapsed at t. Expiry is stored
// with second granularity, so a lease expiring exactly at t counts as expired.
func (r *Record) expired(t time.Time) bool {
	return r.expires <= t.Unix()
}

// logThrottle paces a log line that one packet can trigger.
//
// Not safe for concurrent use and carries no lock of its own: each instance
// has one owner, either the plugin lock or the writer goroutine.
type logThrottle struct {
	last    time.Time
	skipped uint64
}

// ready reports whether a line may go out now, and how many were suppressed
// since the last one that did. The first call always lets one through.
func (t *logThrottle) ready(now time.Time, every time.Duration) (uint64, bool) {
	if !t.last.IsZero() && now.Sub(t.last) < every {
		t.skipped++
		return 0, false
	}
	skipped := t.skipped
	t.skipped, t.last = 0, now
	return skipped, true
}

// pluginState is the data held by an instance of the range plugin
type pluginState struct {
	// Rough lock for the whole plugin, we'll get better performance once we use leasestorage
	sync.Mutex
	// Recordsv4 holds a MAC -> IP address and lease time mapping
	Recordsv4 map[string]*Record
	LeaseTime time.Duration
	leasedb   *sql.DB
	allocator allocators.Allocator

	// declined maps an address to the moment its probation ends. An entry
	// here has no lease and no database row, but its bit is still set in the
	// allocator, which is what actually keeps it out of circulation. Guarded
	// by the plugin lock, like Recordsv4, and initialized alongside it.
	declined map[string]time.Time

	// poolSize is how many addresses the configured range holds. It is what
	// the declineMax default is derived from, and it is the number setup logs
	// so an operator can see the quarantine bound in proportion.
	poolSize uint64

	// name identifies this instance to a lease reader, and poolRange spells
	// the configured range out for one. Both are built during setup and
	// read-only afterwards; see leases.go.
	name      string
	poolRange string

	// sweepInterval is how often the background sweeper reclaims expired
	// leases, declineProbation how long a declined address is held back, and
	// declineMax how many may be held back at once, and maxLeases how many
	// leases the instance may hold before it turns new clients away. All
	// four are set during setup and read-only afterwards.
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int
	maxLeases        int

	// leaseLimit paces the log line saying the lease table is full. Guarded
	// by the plugin lock, like the table it counts.
	leaseLimit logThrottle

	// dbCtx is the plugin's own lifetime and not a request's: the writer
	// outlives the packet that queued a change, and a handler may not hold on
	// to the context it was called with. dbCancel ends it once the writer has
	// drained.
	//nolint:containedctx // the plugin instance's own lifetime, not a request's
	dbCtx    context.Context
	dbCancel context.CancelFunc

	// writes carries lease changes to the writer goroutine. All three are nil
	// until startWriter runs, which is what makes a state built by hand write
	// inline; see storage.go.
	writes     chan leaseWrite
	stopWrites chan struct{}
	writerDone chan struct{}

	// pending holds the changes queued since the lock was taken. Guarded by
	// the plugin lock and emptied by withLock before the lock is released, so
	// it only ever holds one caller's writes.
	pending []pendingWrite

	// now is the clock seam. It is written once during setup, before the
	// sweeper goroutine starts, and only read afterwards. Use timeNow rather
	// than calling it directly: a zero-valued pluginState (which the tests
	// build) leaves it nil.
	now func() time.Time

	// stop closes to shut the background sweeper down; done closes once it
	// has exited. The server never stops a plugin, so nothing closes stop in
	// production -- it exists so tests can reap the goroutine deterministically
	// instead of leaking one per test.
	stop chan struct{}
	done chan struct{}
}

// timeNow reads the clock through the seam, falling back to time.Now so a
// zero-valued pluginState still works.
func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// withLock runs fn under the plugin lock and hands back the lease writes it
// queued, which the caller waits for with settle once the lock is free.
//
// Taking the queued writes while the lock is still held is what makes them
// this caller's and nobody else's.
func (p *pluginState) withLock(fn func()) []pendingWrite {
	p.Lock()
	defer p.Unlock()
	fn()
	return p.takePending()
}

// Handler4 handles DHCPv4 packets for the range plugin.
//
// RELEASE and DECLINE do their bookkeeping and then hand the response on
// untouched. The server sends nothing back for either, and a later plugin in
// the chain (a lease hook, DDNS) still has to see the message, so stopping the
// chain here would cost more than it saves.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	switch req.MessageType() {
	case dhcpv4.MessageTypeInform:
		return resp, false
	case dhcpv4.MessageTypeRelease:
		p.handleRelease(req)
		return resp, false
	case dhcpv4.MessageTypeDecline:
		p.handleDecline(req)
		return resp, false
	}

	mac := req.ClientHWAddr.String()
	hostname := clientHostname(req)

	var ip net.IP
	pending := p.withLock(func() {
		if record := p.leaseFor(mac, p.Recordsv4[mac], hostname); record != nil {
			// Copied out under the lock: once it is released the record
			// belongs to whoever takes the lock next.
			ip = record.IP
		}
	})

	// The reply waits for the lease to reach the disk: a client told it holds
	// an address that a crash then forgets would find it handed to the next
	// client at the following start.
	if err := p.settle(pending); err != nil {
		log.Errorf("Not leasing to MAC %s, its lease could not be written: %v; the client will retry, check the lease database is writable and not held by another process", mac, err)
		return nil, true
	}
	if ip == nil {
		return nil, true
	}

	resp.YourIPAddr = ip
	resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(p.LeaseTime.Round(time.Second)))
	log.Printf("found IP address %s for MAC %s", ip, mac)
	return resp, false
}

// clientHostname reads the name the client asks to be known by, from option
// 12. Nothing in the plugin acts on it; it is filtered and truncated because
// RFC 3396 lets a client split an option across several instances that the
// decoder joins back together, so option 12 can arrive as tens of kilobytes
// and go straight into the lease row and back out through the lease API.
func clientHostname(req *dhcpv4.DHCPv4) string {
	name := strings.Map(func(r rune) rune {
		if strings.ContainsRune(hostnameChars, r) {
			return r
		}
		return -1
	}, req.HostName())
	if len(name) > maxHostnameLen {
		return name[:maxHostnameLen]
	}
	return name
}

// leaseFor returns the lease to answer mac with, allocating or renewing as
// needed. record is the client's current lease, or nil if it has none. A nil
// return means no address could be provided and the request must be dropped.
// The caller must hold p's lock.
func (p *pluginState) leaseFor(mac string, record *Record, hostname string) *Record {
	now := p.timeNow()
	switch {
	case record == nil:
		log.Printf("MAC address %s is new, leasing new IPv4 address", mac)
		return p.allocateLease(mac, net.IPNet{}, hostname, now)
	case record.expired(now):
		return p.reallocateExpired(mac, record, hostname, now)
	case !p.renew(mac, record, hostname, now):
		return nil
	default:
		return record
	}
}

// allocateLease hands mac a fresh address, persists it and tracks it in
// memory. hint is the zero net.IPNet for a client we've never seen, or the
// address it held before its lease lapsed; the bitmap allocator honours a hint
// whenever that address is still free. A nil return means the pool is
// exhausted, the lease table is at its bound, or the lease could not be
// persisted. The caller must hold p's lock.
func (p *pluginState) allocateLease(mac string, hint net.IPNet, hostname string, now time.Time) *Record {
	if p.atLeaseLimit(now) {
		return nil
	}
	ip, err := p.allocate(hint)
	if err != nil {
		log.Errorf("Could not allocate an address for MAC %s: %v; the client will retry, widen the pool or shorten the lease time if this keeps happening", mac, err)
		return nil
	}
	rec := &Record{
		IP:       ip.IP.To4(),
		expires:  now.Add(p.LeaseTime).Unix(),
		hostname: hostname,
	}
	// Handing out an address we could not record would put a second client on
	// it after a restart, so the address goes back whether the write is
	// refused now or fails later.
	if err := p.saveIPAddress(mac, rec, func() { p.dropUnwritten(mac, rec) }); err != nil {
		log.Errorf("Could not write the lease for MAC %s, so it was not handed out: %v; check the lease database is writable and not held by another process", mac, err)
		p.freeUnrecorded(rec)
		return nil
	}
	p.Recordsv4[mac] = rec
	return rec
}

// dropUnwritten takes back a lease whose row did not make it to disk.
//
// Only if the record is still the one this write was for: a release, or a
// later lease for the same client, has already dealt with the address by
// then, and returning it a second time would take it from whoever holds it
// now. The caller must hold p's lock.
func (p *pluginState) dropUnwritten(mac string, rec *Record) {
	if p.Recordsv4[mac] != rec {
		return
	}
	delete(p.Recordsv4, mac)
	p.freeUnrecorded(rec)
}

// freeUnrecorded returns an address to the pool whose lease was never
// recorded, so nothing else can be holding it. The caller must hold p's
// lock.
func (p *pluginState) freeUnrecorded(rec *Record) {
	if err := p.allocator.Free(net.IPNet{IP: rec.IP}); err != nil {
		log.Errorf("Could not return the unrecorded address %s to the pool: %v; it stays out of circulation until the server is restarted", rec.IP, err)
	}
}

// atLeaseLimit reports whether the lease table has reached max-leases, and
// logs the refusal at a pace an operator can read. A bound of zero means the
// operator turned it off. The caller must hold p's lock.
func (p *pluginState) atLeaseLimit(now time.Time) bool {
	if p.maxLeases == 0 || len(p.Recordsv4) < p.maxLeases {
		return false
	}
	// A table full of lapsed leases is a reason to sweep, not to turn a
	// client away: the sweeper would return them, but not for up to half a
	// lease time. Same bargain the allocation path makes when the pool looks
	// exhausted.
	p.reclaim(now)
	if len(p.Recordsv4) < p.maxLeases {
		return false
	}
	if skipped, ok := p.leaseLimit.ready(now, leaseLimitEvery); ok {
		log.Warningf("Holding %d leases, the %s bound, so new clients are turned away (%d refusal(s) since the last of these); raise %s or shorten the lease time",
			p.maxLeases, maxLeasesArg, skipped, maxLeasesArg)
	}
	return true
}

// allocate asks the allocator for an address, and on failure reclaims what has
// lapsed and retries, ending a quarantine early as a last resort.
//
// The sweep is the O(len(Recordsv4)) part of reclamation, so it deliberately
// only runs when an allocation has actually failed. Sweeping before every
// allocation instead would put a full-map scan on the new-client path, which
// is exactly the path a boot storm hammers. In steady state the background
// sweeper keeps the pool clear and this stays a single allocator call.
//
// The caller must hold p's lock.
func (p *pluginState) allocate(hint net.IPNet) (net.IPNet, error) {
	ip, err := p.allocator.Allocate(hint)
	if err == nil {
		return ip, nil
	}
	if freed := p.reclaim(p.timeNow()); freed > 0 {
		if ip, err = p.allocator.Allocate(hint); err == nil {
			return ip, nil
		}
	}
	if !p.evictOldestDeclined() {
		return net.IPNet{}, err
	}
	return p.allocator.Allocate(hint)
}

// evictOldestDeclined ends the probation of the address held back longest and
// returns it to the pool. It reports whether anything was evicted.
//
// This runs only once the allocator has failed twice, so the scan of
// p.declined stays off the path a boot storm takes. A client with no address
// at all is worse off than one handed an address it may have to decline again,
// so an exhausted pool takes the quarantine apart rather than turning clients
// away. The caller must hold p's lock.
func (p *pluginState) evictOldestDeclined() bool {
	var oldest string
	var until time.Time
	for ip, t := range p.declined {
		if oldest == "" || t.Before(until) {
			oldest, until = ip, t
		}
	}
	if oldest == "" {
		return false
	}
	if err := p.allocator.Free(net.IPNet{IP: net.ParseIP(oldest)}); err != nil {
		log.Errorf("Could not end the probation of declined address %s: %v; it stays out of the pool until the server is restarted", oldest, err)
		return false
	}
	delete(p.declined, oldest)
	log.Infof("Pool exhausted, ending the probation of declined address %s early", oldest)
	return true
}

// reallocateExpired handles a client coming back after its lease lapsed but
// before the sweeper reclaimed it. The stale record is not served verbatim:
// the address goes back to the pool and is allocated again, hinting at the
// same address so a late client keeps it as long as nobody else has taken it.
// The caller must hold p's lock.
func (p *pluginState) reallocateExpired(mac string, record *Record, hostname string, now time.Time) *Record {
	log.Printf("lease on %s for MAC %s has expired, re-allocating", record.IP, mac)
	hint := net.IPNet{IP: record.IP}
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not reclaim the expired lease for MAC %s: %v; the client keeps the address it has and the next sweep will try again", mac, err)
		// The address is still spoken for somewhere (a row we failed to
		// delete, or an allocator that would not free it), so allocating
		// again could hand a second client the same address. Keep this client
		// where it is and let the next sweep retry.
		p.Recordsv4[mac] = record
		if !p.renew(mac, record, hostname, now) {
			return nil
		}
		return record
	}
	return p.allocateLease(mac, hint, hostname, now)
}

// renew extends record's lease so it outlives the lease time we are about to
// advertise, and persists the change. A lease with enough time left is left
// untouched. It reports whether the client can be answered with this lease:
// an extension that cannot be written is rolled back, because the reply
// would otherwise name a lease time the lease file does not know about. The
// caller must hold p's lock.
func (p *pluginState) renew(mac string, record *Record, hostname string, now time.Time) bool {
	// Ensure we extend the existing lease at least past when the one we're giving expires
	if !time.Unix(record.expires, 0).Before(now.Add(p.LeaseTime)) {
		return true
	}
	was, wasHostname := record.expires, record.hostname
	record.expires = now.Add(p.LeaseTime).Round(time.Second).Unix()
	record.hostname = hostname
	extended := record.expires
	undo := func() {
		// Only if nothing has moved it on since: a renewal that landed
		// after this one is the client's current lease, not ours to shorten.
		if record.expires == extended {
			record.expires, record.hostname = was, wasHostname
		}
	}
	if err := p.saveIPAddress(mac, record, undo); err != nil {
		log.Errorf("Could not write the renewed lease for MAC %s: %v; the client will retry, check the lease database is writable and not held by another process", mac, err)
		undo()
		return false
	}
	return true
}

// releaseLease returns record's address to the pool: it deletes the row from
// storage, drops the in-memory record, then frees the address in the
// allocator. Storage goes first on purpose -- a lease we cannot forget on disk
// must not be handed to a second client, because a restart would reload the
// row and re-allocate the address to its original owner. The caller must hold
// p's lock.
func (p *pluginState) releaseLease(mac string, record *Record) error {
	if err := p.freeIPAddress(mac, record); err != nil {
		return fmt.Errorf("removing lease from storage: %w", err)
	}
	delete(p.Recordsv4, mac)
	if err := p.allocator.Free(net.IPNet{IP: record.IP}); err != nil {
		return fmt.Errorf("freeing IP %s in the allocator: %w", record.IP, err)
	}
	return nil
}

// handleRelease frees the lease a DHCPRELEASE names, when the sender really
// holds it.
//
// RFC 2131 §4.4.6 puts the address being given up in ciaddr, and that is the
// only thing tying the message to a lease. Freeing on the source MAC alone let
// anyone on the segment empty the pool, and a release from a MAC with no lease
// fell through to the allocation path and handed out an address. Both cases
// now change nothing. Nothing is ever sent in reply, so failures are logged
// and dropped here.
func (p *pluginState) handleRelease(req *dhcpv4.DHCPv4) {
	if err := p.settle(p.withLock(func() { p.release(req) })); err != nil {
		log.Errorf("Could not record the release from MAC %s: %v; the lease stays until it expires, check the lease database is writable and not held by another process", req.ClientHWAddr, err)
	}
}

// release frees the lease a DHCPRELEASE names. The caller must hold p's
// lock; handleRelease is what waits for the row to go.
func (p *pluginState) release(req *dhcpv4.DHCPv4) {
	mac := req.ClientHWAddr.String()
	record, ok := p.Recordsv4[mac]
	if !ok {
		log.Infof("Ignoring RELEASE from MAC %s: it holds no lease", mac)
		return
	}
	if !record.IP.Equal(req.ClientIPAddr) {
		log.Infof("Ignoring RELEASE of %s from MAC %s: it holds %s", req.ClientIPAddr, mac, record.IP)
		return
	}
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not release the lease for MAC %s: %v; it stays until it expires, check the lease database is writable and not held by another process", mac, err)
		return
	}
	log.Printf("Released IP address %s for MAC %s", record.IP, mac)
}

// handleDecline takes the address a DHCPDECLINE reports as already in use out
// of circulation.
//
// RFC 2131 §4.3.3 carries the declined address in option 50, not in ciaddr,
// which is zero in a DHCPDECLINE. As with a release, only the client that
// actually holds the address may decline it, and a decline never allocates.
func (p *pluginState) handleDecline(req *dhcpv4.DHCPv4) {
	if err := p.settle(p.withLock(func() { p.decline(req) })); err != nil {
		log.Errorf("Could not record the decline from MAC %s: %v; the address stays leased until it expires, check the lease database is writable", req.ClientHWAddr, err)
	}
}

// decline takes the address a DHCPDECLINE names out of circulation. The
// caller must hold p's lock; handleDecline is what waits for the row to go.
func (p *pluginState) decline(req *dhcpv4.DHCPv4) {
	mac := req.ClientHWAddr.String()
	declined := req.RequestedIPAddress()
	record, ok := p.Recordsv4[mac]
	if !ok {
		log.Infof("Ignoring DECLINE of %s from MAC %s: it holds no lease", declined, mac)
		return
	}
	if !record.IP.Equal(declined) {
		log.Infof("Ignoring DECLINE of %s from MAC %s: it holds %s", declined, mac, record.IP)
		return
	}
	p.quarantine(mac, record)
}

// quarantine drops a declined lease and holds its address back from the pool
// for declineProbation, as long as the quarantine has room.
//
// The client just told us the address is already in use on the link, so
// handing it to the next client would repeat the conflict. The record and the
// row go, but the allocator bit stays set, which is what keeps the address out
// of circulation; p.declined only records when it may come back.
//
// Holding addresses back without a limit is what let two forged packets per
// address park a whole pool for a day, so this is best effort: with either
// knob set to zero, or with declineMax addresses already held back, the
// declined address goes straight back to the pool instead. The caller must
// hold p's lock.
func (p *pluginState) quarantine(mac string, record *Record) {
	if p.declineProbation == 0 || p.declineMax == 0 {
		p.freeDeclined(mac, record)
		return
	}
	if len(p.declined) >= p.declineMax {
		log.Infof("Quarantine full at %d address(es), not holding %s back for MAC %s", p.declineMax, record.IP, mac)
		p.freeDeclined(mac, record)
		return
	}
	if err := p.freeIPAddress(mac, record); err != nil {
		log.Errorf("Could not remove the declined lease for MAC %s from storage: %v; it stays until it expires, check the lease database is writable", mac, err)
		return
	}
	delete(p.Recordsv4, mac)

	until := p.timeNow().Add(p.declineProbation)
	p.declined[record.IP.String()] = until
	log.Printf("MAC %s declined %s, holding it back until %s", mac, record.IP, until)
}

// freeDeclined hands a declined address straight back to the pool, for the
// cases where no quarantine applies. The caller must hold p's lock.
func (p *pluginState) freeDeclined(mac string, record *Record) {
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not free the declined lease for MAC %s: %v; it stays until it expires, check the lease database is writable", mac, err)
		return
	}
	log.Printf("Freed declined IP address %s for MAC %s", record.IP, mac)
}

// sweepExpired frees every lease that had expired at t and reports how many
// addresses went back to the pool. A record whose storage row cannot be
// deleted is logged and skipped rather than aborting the sweep, so one wedged
// row never stops the rest from being reclaimed. The caller must hold p's lock.
func (p *pluginState) sweepExpired(t time.Time) int {
	var freed int
	for mac, record := range p.Recordsv4 {
		if !record.expired(t) {
			continue
		}
		if err := p.releaseLease(mac, record); err != nil {
			log.Errorf("Could not reclaim the expired lease for MAC %s while sweeping: %v; check the lease database is writable and not held by another process", mac, err)
			continue
		}
		freed++
	}
	return freed
}

// sweepDeclined returns to the pool every address whose probation had ended at
// t, and reports how many.
//
// This is the only thing that walks p.declined. The allocation path must not
// pay for a map scan per client, and it does not have to: a quarantined
// address is simply a bit the allocator still has set, so it is never offered
// until this runs. The caller must hold p's lock.
func (p *pluginState) sweepDeclined(t time.Time) int {
	var freed int
	for ip, until := range p.declined {
		if until.After(t) {
			continue
		}
		if err := p.allocator.Free(net.IPNet{IP: net.ParseIP(ip)}); err != nil {
			log.Errorf("Could not return the declined address %s to the pool: %v; it stays out of circulation until the server is restarted", ip, err)
			continue
		}
		delete(p.declined, ip)
		freed++
	}
	return freed
}

// reclaim frees everything that is no longer spoken for at t: leases that have
// expired, and declined addresses whose probation has ended. It reports how
// many addresses went back to the pool. The caller must hold p's lock.
func (p *pluginState) reclaim(t time.Time) int {
	return p.sweepExpired(t) + p.sweepDeclined(t)
}

// sweepOnce takes the lock and reclaims every expired lease and every declined
// address whose probation has run out.
func (p *pluginState) sweepOnce() {
	var freed int
	pending := p.withLock(func() { freed = p.reclaim(p.timeNow()) })
	if err := p.settle(pending); err != nil {
		log.Errorf("Could not clear a reclaimed lease from storage: %v; check the lease database is writable and not held by another process", err)
	}
	if freed > 0 {
		log.Printf("Returned %d DHCPv4 address(es) to the pool", freed)
	}
}

// startSweeper runs the background reclamation loop. Like the file plugin's
// autorefresh watcher it lives for the lifetime of the process -- plugins are
// never stopped or unregistered -- but it still honours p.stop so tests can
// shut it down.
func (p *pluginState) startSweeper(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.sweepOnce()
			}
		}
	}()
}

// stopSweeper shuts the background sweeper down and waits for it to exit.
// Nothing in the server calls this; it exists so a test does not leave a
// goroutine running after it finishes.
func (p *pluginState) stopSweeper() {
	close(p.stop)
	<-p.done
}

// Close stops this instance's background goroutines and flushes the lease
// writes it still has queued. Call it once, and only on an instance setup
// built.
//
// Nothing in the server calls it: plugins are set up once and live as long
// as the process. It is here for an embedding program and for the black-box
// tests, which would otherwise leave a sweeper and a writer running over a
// lease file they are about to delete.
func (p *pluginState) Close() {
	p.stopSweeper()
	p.stopWriter()
}

// defaultSweepInterval derives the sweep period from the lease time: half a
// lease, so an address is back in the pool well within one lease of lapsing,
// floored at minSweepInterval.
func defaultSweepInterval(leaseTime time.Duration) time.Duration {
	if half := leaseTime / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// poolSize counts the addresses in the inclusive range [start, end]. Both are
// known to be IPv4 addresses, with start no higher than end, by the time this
// runs.
//
// The count is kept in uint64 rather than uint: a range covering the whole
// address space holds 2^32 addresses, which wraps back to zero in the 32 bits
// uint has on a 32-bit build.
func poolSize(start, end net.IP) uint64 {
	first := binary.BigEndian.Uint32(start.To4())
	last := binary.BigEndian.Uint32(end.To4())
	return uint64(last-first) + 1
}

// defaultDeclineMax sets the quarantine to a share of the pool, held between
// one address, so decline-probation still does something on a pool of two, and
// maxDeclineQuarantine.
func defaultDeclineMax(size uint64) int {
	share := size / declineQuarantineShare
	if share > maxDeclineQuarantine {
		return maxDeclineQuarantine
	}
	if share < 1 {
		return 1
	}
	return int(share)
}

// pluginOptions holds the settings taken from the optional key:value arguments
// that may follow the four positional ones.
type pluginOptions struct {
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int
	maxLeases        int
}

// optionParsers dispatches on the argument key. parseOptions handles ordering,
// duplicates and unknown keys for every entry here, so accepting another
// argument is one line plus its parser.
var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:      parseSweepInterval,
	declineArg:    parseDeclineProbation,
	declineMaxArg: parseDeclineMax,
	maxLeasesArg:  parseMaxLeases,
}

// parseOptions reads the optional key:value arguments, which may come in any
// order. extra holds whatever followed the four required arguments, and size
// the number of addresses in the pool, which the decline-max default is
// derived from. An unknown key, or a key given twice, is an error rather than
// something quietly ignored: a typo must not leave the operator with a default
// they believe they overrode.
func parseOptions(leaseTime time.Duration, size uint64, extra []string) (pluginOptions, error) {
	opts := pluginOptions{
		sweepInterval:    defaultSweepInterval(leaseTime),
		declineProbation: defaultDeclineProbation,
		declineMax:       defaultDeclineMax(size),
		maxLeases:        defaultMaxLeases,
	}
	seen := make(map[string]bool, len(extra))
	for _, arg := range extra {
		key, value, hasValue := strings.Cut(arg, ":")
		parse, known := optionParsers[key]
		if !hasValue || !known {
			return pluginOptions{}, fmt.Errorf("argument %q is not one this plugin takes; use %s, or leave them out for their defaults", arg, optionSyntax)
		}
		if seen[key] {
			return pluginOptions{}, fmt.Errorf("argument %s is given more than once; keep one and remove the rest", key)
		}
		seen[key] = true
		if err := parse(&opts, value); err != nil {
			return pluginOptions{}, err
		}
	}
	return opts, nil
}

// parseSweepInterval reads the value of a "sweep:" argument.
func parseSweepInterval(opts *pluginOptions, raw string) error {
	interval, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("%s:%s is not a duration: %w; use a Go duration such as 5m, or leave it out for half the lease time, floored at %s",
			sweepArg, raw, err, minSweepInterval)
	}
	if interval <= 0 {
		return fmt.Errorf("%s:%s is not above zero; use a duration such as 5m, or leave it out for half the lease time, floored at %s",
			sweepArg, raw, minSweepInterval)
	}
	opts.sweepInterval = interval
	return nil
}

// parseDeclineProbation reads the value of a "decline-probation:" argument.
// Zero is allowed and means no quarantine at all; a negative probation is not,
// because it would read as "hold it back for a while" and do the opposite.
func parseDeclineProbation(opts *pluginOptions, raw string) error {
	probation, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("%s:%s is not a duration: %w; use a Go duration such as 1h, or leave it out for the default of %s",
			declineArg, raw, err, defaultDeclineProbation)
	}
	if probation < 0 {
		return fmt.Errorf("%s:%s is negative; use 0 to hand a declined address straight back, or a duration such as 1h",
			declineArg, raw)
	}
	opts.declineProbation = probation
	return nil
}

// parseDeclineMax reads the value of a "decline-max:" argument. Zero is
// allowed and turns the quarantine off; a negative count is not, because it
// would read as a limit and act as none at all.
func parseDeclineMax(opts *pluginOptions, raw string) error {
	count, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("%s:%s is not a number: %w; use a count such as 8, 0 to turn the quarantine off, or leave it out for a tenth of the pool",
			declineMaxArg, raw, err)
	}
	if count < 0 {
		return fmt.Errorf("%s:%s is negative; use 0 to turn the quarantine off, or a count such as 8", declineMaxArg, raw)
	}
	opts.declineMax = count
	return nil
}

// parseMaxLeases reads the value of a "max-leases:" argument. Zero turns the
// bound off; a negative count is refused because it would read as a limit
// and act as none at all.
func parseMaxLeases(opts *pluginOptions, raw string) error {
	count, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("%s:%s is not a number: %w; use a count such as 4096, 0 to turn the bound off, or leave it out for the default of %d",
			maxLeasesArg, raw, err, defaultMaxLeases)
	}
	if count < 0 {
		return fmt.Errorf("%s:%s is negative; use 0 to turn the bound off, or a count such as 4096", maxLeasesArg, raw)
	}
	opts.maxLeases = count
	return nil
}

// setupRange builds the plugin instance and starts its background sweeper.
func setupRange(args ...string) (handler.Handler4, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Both started only once setup has fully succeeded: a failed setup must
	// not leave goroutines behind serving a half-built plugin. The writer
	// goes first, because from here on the sweeper can queue deletes.
	p.startWriter()
	p.startSweeper(p.sweepInterval)
	// Registered last, once everything that could fail has succeeded: a
	// reader must never find a half-built instance in the registry.
	leases.Register(p)
	log.Printf("Serving %d addresses, reclaiming expired DHCPv4 leases every %s, declined addresses after %s, quarantining at most %d at a time, holding at most %d leases",
		p.poolSize, p.sweepInterval, p.declineProbation, p.declineMax, p.maxLeases)
	// poolSizeAsInt saturates rather than wraps, which is also what makes
	// the comparison safe on a 32-bit build.
	if size := poolSizeAsInt(p.poolSize); p.maxLeases > 0 && size > p.maxLeases {
		log.Warningf("The pool holds %d addresses but %s bounds the lease table at %d, so the last %d will never be handed out; raise %s or narrow the pool",
			size, maxLeasesArg, p.maxLeases, size-p.maxLeases, maxLeasesArg)
	}
	return p.Handler4, nil
}

// newPluginState validates the plugin arguments and builds a ready but idle
// instance: storage is open and the leases are loaded and re-allocated, but no
// sweeper is running yet. setupRange starts it; tests that need to own the
// goroutine's lifetime call this directly.
func newPluginState(args ...string) (*pluginState, error) {
	var err error
	p := &pluginState{
		declined: make(map[string]time.Time),
		now:      time.Now,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	p.dbCtx, p.dbCancel = context.WithCancel(context.Background())

	if len(args) < 4 {
		return nil, fmt.Errorf("got %d arguments, want at least 4; pass <lease file> <first address> <last address> <lease time>, such as leases.sqlite3 10.0.0.100 10.0.0.200 1h", len(args))
	}
	filename := args[0]
	if filename == "" {
		return nil, errors.New("the lease file name is empty; give a path the server's user may write, such as /var/lib/coredhcp/leases.sqlite3")
	}
	ipRangeStart := net.ParseIP(args[1])
	if ipRangeStart.To4() == nil {
		return nil, fmt.Errorf("the first pool address %q is not IPv4; write it in dotted-quad notation, such as 10.0.0.100", args[1])
	}
	ipRangeEnd := net.ParseIP(args[2])
	if ipRangeEnd.To4() == nil {
		return nil, fmt.Errorf("the last pool address %q is not IPv4; write it in dotted-quad notation, such as 10.0.0.200", args[2])
	}
	if binary.BigEndian.Uint32(ipRangeStart.To4()) > binary.BigEndian.Uint32(ipRangeEnd.To4()) {
		return nil, errors.New("the first pool address is above the last; swap the two arguments")
	}

	p.allocator, err = newIPv4Allocator(ipRangeStart, ipRangeEnd)
	if err != nil {
		return nil, fmt.Errorf("could not build the address allocator: %w; check the two pool addresses", err)
	}

	p.LeaseTime, err = time.ParseDuration(args[3])
	if err != nil {
		return nil, fmt.Errorf("lease time %q is not a duration; use a Go duration such as 1h or 30m", args[3])
	}

	p.poolSize = poolSize(ipRangeStart, ipRangeEnd)
	p.name = "range " + filename
	p.poolRange = ipRangeStart.String() + "-" + ipRangeEnd.String()
	opts, err := parseOptions(p.LeaseTime, p.poolSize, args[4:])
	if err != nil {
		return nil, err
	}
	p.sweepInterval = opts.sweepInterval
	p.declineProbation = opts.declineProbation
	p.declineMax = opts.declineMax
	p.maxLeases = opts.maxLeases

	if err = p.registerBackingDB(p.dbCtx, filename); err != nil {
		return nil, fmt.Errorf("could not setup lease storage: %w", err)
	}
	// The leases already on disk count against max-leases: a table over the
	// bound at startup hands out nothing new until it shrinks.
	p.Recordsv4, err = loadRecords(p.dbCtx, p.leasedb)
	if err != nil {
		return nil, fmt.Errorf("could not load the leases in %s: %w; check the server's user may read the file and that no other process holds it", filename, err)
	}

	log.Printf("Loaded %d DHCPv4 leases from %s", len(p.Recordsv4), filename)

	for _, v := range p.Recordsv4 {
		ip, err := p.allocator.Allocate(net.IPNet{IP: v.IP})
		if err != nil {
			return nil, fmt.Errorf("the stored lease on %v does not fit the configured pool: %w; widen the pool, or delete that row from %s", v.IP, err, filename)
		}
		if ip.IP.String() != v.IP.String() {
			return nil, fmt.Errorf("the stored lease on %v sits outside the configured pool, the allocator offered %v instead; widen the pool, or delete that row from %s", v.IP, ip.IP, filename)
		}
	}

	return p, nil
}
