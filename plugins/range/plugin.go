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
// An optional fifth argument, sweep:<duration>, sets how often expired leases
// are reclaimed in the background. It defaults to half the lease time, floored
// at 30s.
//
// Leases are reclaimed in two places: a background sweeper on a ticker, and
// lazily on the allocation path when the pool looks exhausted. Without either,
// expired leases pile up in the map, the allocator and the database forever,
// and a stable population of churning clients eventually exhausts the pool
// permanently (upstream issues #148 and #182).
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
	// sweepArgPrefix marks the optional trailing argument that overrides the
	// background sweep interval, e.g. "sweep:5m".
	sweepArgPrefix = "sweep:"

	// minSweepInterval floors the derived sweep interval. A short lease time
	// (a captive portal handing out 30s leases, say) must not turn the
	// sweeper into a hot loop taking the plugin lock.
	minSweepInterval = 30 * time.Second
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

	// sweepInterval is how often the background sweeper reclaims expired
	// leases. Set during setup and read-only afterwards.
	sweepInterval time.Duration

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

// Handler4 handles DHCPv4 packets for the range plugin
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.MessageType() == dhcpv4.MessageTypeInform {
		return resp, false
	}
	p.Lock()
	defer p.Unlock()

	mac := req.ClientHWAddr.String()
	record, ok := p.Recordsv4[mac]

	if ok && req.MessageType() == dhcpv4.MessageTypeRelease {
		p.handleRelease(mac, record)
		return nil, true
	}

	record = p.leaseFor(mac, record, req.HostName())
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

// allocate asks the allocator for an address, and on failure sweeps expired
// leases and retries once.
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
	if freed := p.sweepExpired(p.timeNow()); freed == 0 {
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

// handleRelease frees the lease for a client that sent a DHCPRELEASE. The DHCP
// response to a release is always "no response, stop processing", so failures
// are only logged here. The caller must hold p's lock.
func (p *pluginState) handleRelease(mac string, record *Record) {
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not release lease for MAC %s: %v", mac, err)
		return
	}
	log.Printf("Released IP address %s for MAC %s", record.IP, mac)
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

// sweepOnce takes the lock and reclaims every expired lease.
func (p *pluginState) sweepOnce() {
	p.Lock()
	defer p.Unlock()
	if freed := p.sweepExpired(p.timeNow()); freed > 0 {
		log.Printf("Reclaimed %d expired DHCPv4 lease(s)", freed)
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

// parseSweepInterval reads the optional trailing "sweep:<duration>" argument,
// falling back to defaultSweepInterval. extra holds whatever followed the four
// required arguments; anything that is not a sweep argument is rejected rather
// than silently ignored.
func parseSweepInterval(leaseTime time.Duration, extra []string) (time.Duration, error) {
	if len(extra) == 0 {
		return defaultSweepInterval(leaseTime), nil
	}
	if len(extra) > 1 {
		return 0, fmt.Errorf("too many arguments, want at most 5 (file name, start IP, end IP, lease time, %s<duration>), got: %d", sweepArgPrefix, len(extra)+4)
	}
	raw, ok := strings.CutPrefix(extra[0], sweepArgPrefix)
	if !ok {
		return 0, fmt.Errorf("unexpected argument %q, want %s<duration>", extra[0], sweepArgPrefix)
	}
	interval, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid sweep interval: %v", raw)
	}
	if interval <= 0 {
		return 0, fmt.Errorf("sweep interval has to be positive, got: %v", raw)
	}
	return interval, nil
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
	log.Printf("Reclaiming expired DHCPv4 leases every %s", p.sweepInterval)
	return p.Handler4, nil
}

// newPluginState validates the plugin arguments and builds a ready but idle
// instance: storage is open and the leases are loaded and re-allocated, but no
// sweeper is running yet. setupRange starts it; tests that need to own the
// goroutine's lifetime call this directly.
func newPluginState(args ...string) (*pluginState, error) {
	var err error
	p := &pluginState{
		now:  time.Now,
		stop: make(chan struct{}),
		done: make(chan struct{}),
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

	p.sweepInterval, err = parseSweepInterval(p.LeaseTime, args[4:])
	if err != nil {
		return nil, err
	}

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
