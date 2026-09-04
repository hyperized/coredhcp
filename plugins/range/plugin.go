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
// Two optional arguments may follow, in either order:
//
//	sweep:<duration>              how often expired leases are reclaimed in
//	                              the background. Defaults to half the lease
//	                              time, floored at 30s.
//	decline-probation:<duration>  how long an address a client declined is
//	                              held back from the pool. Defaults to 24h,
//	                              the same as Kea. 0 hands a declined address
//	                              straight back out.
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
package rangeplugin

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/handler"
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

	// optionSyntax spells the optional arguments out for error messages.
	optionSyntax = sweepArg + ":<duration> or " + declineArg + ":<duration>"

	// minSweepInterval floors the derived sweep interval. A short lease time
	// (a captive portal handing out 30s leases, say) must not turn the
	// sweeper into a hot loop taking the plugin lock.
	minSweepInterval = 30 * time.Second

	// defaultDeclineProbation is what Kea uses for decline-probation-period.
	// A day is long enough that whatever was squatting on the address has
	// usually gone, and short enough that one bad afternoon does not bleed a
	// pool dry.
	defaultDeclineProbation = 24 * time.Hour
)

// Record holds an IP lease record
type Record struct {
	IP       net.IP
	expires  int
	hostname string
}

// expired reports whether the lease had already lapsed at t. Expiry is stored
// with second granularity, so a lease expiring exactly at t counts as expired.
func (r *Record) expired(t time.Time) bool {
	return int64(r.expires) <= t.Unix()
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

	// sweepInterval is how often the background sweeper reclaims expired
	// leases. declineProbation is how long a declined address is held back.
	// Both are set during setup and read-only afterwards.
	sweepInterval    time.Duration
	declineProbation time.Duration

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

	p.Lock()
	defer p.Unlock()

	mac := req.ClientHWAddr.String()
	record := p.leaseFor(mac, p.Recordsv4[mac], req.HostName())
	if record == nil {
		return nil, true
	}

	resp.YourIPAddr = record.IP
	resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(p.LeaseTime.Round(time.Second)))
	log.Printf("found IP address %s for MAC %s", record.IP, mac)
	return resp, false
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
	default:
		p.renew(mac, record, hostname, now)
		return record
	}
}

// allocateLease hands mac a fresh address, persists it and tracks it in
// memory. hint is the zero net.IPNet for a client we've never seen, or the
// address it held before its lease lapsed; the bitmap allocator honours a hint
// whenever that address is still free. A nil return means the pool is
// exhausted. The caller must hold p's lock.
func (p *pluginState) allocateLease(mac string, hint net.IPNet, hostname string, now time.Time) *Record {
	ip, err := p.allocate(hint)
	if err != nil {
		log.Errorf("Could not allocate IP for MAC %s: %v", mac, err)
		return nil
	}
	rec := &Record{
		IP:       ip.IP.To4(),
		expires:  int(now.Add(p.LeaseTime).Unix()),
		hostname: hostname,
	}
	if err := p.saveIPAddress(mac, rec); err != nil {
		log.Errorf("SaveIPAddress for MAC %s failed: %v", mac, err)
	}
	p.Recordsv4[mac] = rec
	return rec
}

// allocate asks the allocator for an address, and on failure reclaims what has
// lapsed and retries once.
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
	if freed := p.reclaim(p.timeNow()); freed == 0 {
		return net.IPNet{}, err
	}
	return p.allocator.Allocate(hint)
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
		log.Errorf("Could not reclaim expired lease for MAC %s: %v", mac, err)
		// The address is still spoken for somewhere (a row we failed to
		// delete, or an allocator that would not free it), so allocating
		// again could hand a second client the same address. Keep this client
		// where it is and let the next sweep retry.
		p.Recordsv4[mac] = record
		p.renew(mac, record, hostname, now)
		return record
	}
	return p.allocateLease(mac, hint, hostname, now)
}

// renew extends record's lease so it outlives the lease time we are about to
// advertise, and persists the change. A lease with enough time left is left
// untouched. The caller must hold p's lock.
func (p *pluginState) renew(mac string, record *Record, hostname string, now time.Time) {
	// Ensure we extend the existing lease at least past when the one we're giving expires
	if !time.Unix(int64(record.expires), 0).Before(now.Add(p.LeaseTime)) {
		return
	}
	record.expires = int(now.Add(p.LeaseTime).Round(time.Second).Unix())
	record.hostname = hostname
	if err := p.saveIPAddress(mac, record); err != nil {
		log.Errorf("Could not persist lease for MAC %s: %v", mac, err)
	}
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
	p.Lock()
	defer p.Unlock()

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
		log.Errorf("Could not release lease for MAC %s: %v", mac, err)
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
	p.Lock()
	defer p.Unlock()

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
// for declineProbation.
//
// The client just told us the address is already in use on the link, so
// handing it to the next client would repeat the conflict. The record and the
// row go, but the allocator bit stays set, which is what keeps the address out
// of circulation; p.declined only records when it may come back. A probation
// of zero skips all that and frees the address outright. The caller must hold
// p's lock.
func (p *pluginState) quarantine(mac string, record *Record) {
	if p.declineProbation == 0 {
		if err := p.releaseLease(mac, record); err != nil {
			log.Errorf("Could not free declined lease for MAC %s: %v", mac, err)
			return
		}
		log.Printf("Freed declined IP address %s for MAC %s", record.IP, mac)
		return
	}
	if err := p.freeIPAddress(mac, record); err != nil {
		log.Errorf("Could not remove declined lease for MAC %s from storage: %v", mac, err)
		return
	}
	delete(p.Recordsv4, mac)

	until := p.timeNow().Add(p.declineProbation)
	p.declined[record.IP.String()] = until
	log.Printf("MAC %s declined %s, holding it back until %s", mac, record.IP, until)
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
			log.Errorf("Could not reclaim expired lease for MAC %s: %v", mac, err)
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
			log.Errorf("Could not return declined IP %s to the pool: %v", ip, err)
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
	p.Lock()
	defer p.Unlock()
	if freed := p.reclaim(p.timeNow()); freed > 0 {
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

// defaultSweepInterval derives the sweep period from the lease time: half a
// lease, so an address is back in the pool well within one lease of lapsing,
// floored at minSweepInterval.
func defaultSweepInterval(leaseTime time.Duration) time.Duration {
	if half := leaseTime / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// pluginOptions holds the settings taken from the optional key:value arguments
// that may follow the four positional ones.
type pluginOptions struct {
	sweepInterval    time.Duration
	declineProbation time.Duration
}

// optionParsers dispatches on the argument key. parseOptions handles ordering,
// duplicates and unknown keys for every entry here, so accepting another
// argument is one line plus its parser.
var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:   parseSweepInterval,
	declineArg: parseDeclineProbation,
}

// parseOptions reads the optional key:value arguments, which may come in any
// order. extra holds whatever followed the four required arguments. An unknown
// key, or a key given twice, is an error rather than something quietly
// ignored: a typo must not leave the operator with a default they believe they
// overrode.
func parseOptions(leaseTime time.Duration, extra []string) (pluginOptions, error) {
	opts := pluginOptions{
		sweepInterval:    defaultSweepInterval(leaseTime),
		declineProbation: defaultDeclineProbation,
	}
	seen := make(map[string]bool, len(extra))
	for _, arg := range extra {
		key, value, hasValue := strings.Cut(arg, ":")
		parse, known := optionParsers[key]
		if !hasValue || !known {
			return pluginOptions{}, fmt.Errorf("unexpected argument %q, want %s", arg, optionSyntax)
		}
		if seen[key] {
			return pluginOptions{}, fmt.Errorf("argument %s given more than once", key)
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
		return fmt.Errorf("invalid sweep interval %q: %w", raw, err)
	}
	if interval <= 0 {
		return fmt.Errorf("sweep interval has to be positive, got: %v", raw)
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
		return fmt.Errorf("invalid decline probation %q: %w", raw, err)
	}
	if probation < 0 {
		return fmt.Errorf("decline probation cannot be negative, got: %v", raw)
	}
	opts.declineProbation = probation
	return nil
}

// setupRange builds the plugin instance and starts its background sweeper.
func setupRange(args ...string) (handler.Handler4, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Started only once setup has fully succeeded: a failed setup must not
	// leave a goroutine behind sweeping a half-built plugin.
	p.startSweeper(p.sweepInterval)
	log.Printf("Reclaiming expired DHCPv4 leases every %s, declined addresses after %s", p.sweepInterval, p.declineProbation)
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

	if len(args) < 4 {
		return nil, fmt.Errorf("invalid number of arguments, want: 4 (file name, start IP, end IP, lease time), got: %d", len(args))
	}
	filename := args[0]
	if filename == "" {
		return nil, errors.New("file name cannot be empty")
	}
	ipRangeStart := net.ParseIP(args[1])
	if ipRangeStart.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %v", args[1])
	}
	ipRangeEnd := net.ParseIP(args[2])
	if ipRangeEnd.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %v", args[2])
	}
	if binary.BigEndian.Uint32(ipRangeStart.To4()) > binary.BigEndian.Uint32(ipRangeEnd.To4()) {
		return nil, errors.New("start of IP range has to be lower than or equal to the end of an IP range")
	}

	p.allocator, err = newIPv4Allocator(ipRangeStart, ipRangeEnd)
	if err != nil {
		return nil, fmt.Errorf("could not create an allocator: %w", err)
	}

	p.LeaseTime, err = time.ParseDuration(args[3])
	if err != nil {
		return nil, fmt.Errorf("invalid lease duration: %v", args[3])
	}

	opts, err := parseOptions(p.LeaseTime, args[4:])
	if err != nil {
		return nil, err
	}
	p.sweepInterval = opts.sweepInterval
	p.declineProbation = opts.declineProbation

	if err := p.registerBackingDB(filename); err != nil {
		return nil, fmt.Errorf("could not setup lease storage: %w", err)
	}
	p.Recordsv4, err = loadRecords(p.leasedb)
	if err != nil {
		return nil, fmt.Errorf("could not load records from file: %w", err)
	}

	log.Printf("Loaded %d DHCPv4 leases from %s", len(p.Recordsv4), filename)

	for _, v := range p.Recordsv4 {
		ip, err := p.allocator.Allocate(net.IPNet{IP: v.IP})
		if err != nil {
			return nil, fmt.Errorf("failed to re-allocate leased ip %v: %w", v.IP.String(), err)
		}
		if ip.IP.String() != v.IP.String() {
			return nil, fmt.Errorf("allocator did not re-allocate requested leased ip %v: %v", v.IP.String(), ip.String())
		}
	}

	return p, nil
}
