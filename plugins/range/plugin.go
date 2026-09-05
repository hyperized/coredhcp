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
// Three optional arguments may follow, in any order:
//
//	sweep:<duration>              how often expired leases are reclaimed.
//	                              Defaults to half the lease time, floored at 30s.
//	decline-probation:<duration>  how long a declined address is held back from
//	                              the pool. Defaults to 24h; 0 disables it.
//	decline-max:<count>           how many declined addresses may be held back at
//	                              once. Defaults to a tenth of the pool, clamped
//	                              to [1, 65536]; 0 disables the quarantine.
//
// RELEASE and DECLINE are unauthenticated and trivially forged, so both are
// honoured only from a client that already holds the address they name: in
// ciaddr for a release (RFC 2131 §4.4.6), in option 50 for a decline (§4.3.3).
// A declined address is held back from the pool for the probation period so
// the next client does not walk into the same conflict, but the quarantine is
// bounded so two forged packets per address cannot park the whole pool for a
// day. Probation lives in memory only: a restart returns every held address.
package rangeplugin

import (
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

// newIPv4Allocator is a test seam: setup validates the range first, so the
// allocator's construction error is unreachable through the public API.
var newIPv4Allocator = bitmap.NewIPv4Allocator

const (
	sweepArg = "sweep"

	declineArg = "decline-probation"

	declineMaxArg = "decline-max"

	optionSyntax = sweepArg + ":<duration>, " + declineArg + ":<duration> or " + declineMaxArg + ":<count>"

	// A captive portal handing out 30s leases must not turn the sweeper into a
	// hot loop taking the plugin lock.
	minSweepInterval = 30 * time.Second

	// What Kea uses for decline-probation-period.
	defaultDeclineProbation = 24 * time.Hour

	// A tenth of the pool covers the conflicts a segment produces for real.
	declineQuarantineShare = 10

	// Each quarantined address is a live map entry, so the default is capped
	// however large the pool is; decline-max still overrides it.
	maxDeclineQuarantine = 1 << 16
)

// Record holds an IP lease record
type Record struct {
	IP       net.IP
	expires  int
	hostname string
}

// Expiry has second granularity, so a lease lapsing exactly at t is expired.
func (r *Record) expired(t time.Time) bool {
	return int64(r.expires) <= t.Unix()
}

type pluginState struct {
	sync.Mutex
	// Recordsv4 is keyed by the client MAC as formatted by net.HardwareAddr.String.
	Recordsv4 map[string]*Record
	LeaseTime time.Duration
	leasedb   *sql.DB
	allocator allocators.Allocator

	// declined maps an address to the moment its probation ends. The entry has
	// no lease and no row; the allocator bit stays set, and that is what keeps
	// the address out of circulation.
	declined map[string]time.Time

	poolSize uint64

	name      string
	poolRange string

	// Set during setup, read-only afterwards.
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int

	// Clock seam. Read it through timeNow: a zero-valued pluginState, which
	// the tests build, leaves it nil.
	now func() time.Time

	// Nothing in the server stops a plugin, so these exist only so tests can
	// reap the sweeper instead of leaking one goroutine per test.
	stop chan struct{}
	done chan struct{}
}

func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// Handler4 handles DHCPv4 packets for the range plugin.
//
// RELEASE and DECLINE do their bookkeeping and hand the response on untouched:
// nothing is sent back for either, but later plugins still have to see them.
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

// leaseFor allocates or renews as needed; nil means the request must be
// dropped. The caller must hold p's lock.
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

// hint is zero for an unknown client, or the address it held before its lease
// lapsed; the allocator honours it whenever that address is still free. The
// caller must hold p's lock.
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

// Reclamation runs only after an allocation has failed: sweeping first would
// put an O(len(Recordsv4)) scan on the path a boot storm hammers. The caller
// must hold p's lock.
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

// A client with no address at all is worse off than one handed an address it
// may decline again, so an exhausted pool takes the quarantine apart rather
// than turning clients away. The caller must hold p's lock.
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
		log.Errorf("Could not return declined IP %s to the pool: %v", oldest, err)
		return false
	}
	delete(p.declined, oldest)
	log.Infof("Pool exhausted, ending the probation of declined address %s early", oldest)
	return true
}

// The stale record is not served verbatim: the address goes back to the pool
// and is allocated again with itself as the hint, so a late client keeps it
// only if nobody else has taken it. The caller must hold p's lock.
func (p *pluginState) reallocateExpired(mac string, record *Record, hostname string, now time.Time) *Record {
	log.Printf("lease on %s for MAC %s has expired, re-allocating", record.IP, mac)
	hint := net.IPNet{IP: record.IP}
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not reclaim expired lease for MAC %s: %v", mac, err)
		// The address is still spoken for somewhere, so allocating again
		// could hand a second client the same one. Let the sweep retry.
		p.Recordsv4[mac] = record
		p.renew(mac, record, hostname, now)
		return record
	}
	return p.allocateLease(mac, hint, hostname, now)
}

// The caller must hold p's lock.
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

// Storage row first, then the map, then the allocator bit: a lease we cannot
// forget on disk must not be handed out again, because a restart would reload
// the row and re-allocate it to its original owner. Caller holds p's lock.
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

// RFC 2131 §4.4.6 puts the address being given up in ciaddr, and that is the
// only thing tying the message to a lease; going by the source MAC alone would
// let anyone on the segment empty the pool. Nothing is ever sent in reply.
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

// RFC 2131 §4.3.3 carries the declined address in option 50, not in ciaddr,
// which is zero in a DHCPDECLINE. Only its holder may decline it.
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

// The record and the row go, but the allocator bit stays set: that is what
// keeps the address out of circulation, and p.declined only records when it
// may come back. Best effort -- with either knob at zero, or the quarantine
// full, the address goes straight back to the pool. Caller holds p's lock.
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
		log.Errorf("Could not remove declined lease for MAC %s from storage: %v", mac, err)
		return
	}
	delete(p.Recordsv4, mac)

	until := p.timeNow().Add(p.declineProbation)
	p.declined[record.IP.String()] = until
	log.Printf("MAC %s declined %s, holding it back until %s", mac, record.IP, until)
}

// The caller must hold p's lock.
func (p *pluginState) freeDeclined(mac string, record *Record) {
	if err := p.releaseLease(mac, record); err != nil {
		log.Errorf("Could not free declined lease for MAC %s: %v", mac, err)
		return
	}
	log.Printf("Freed declined IP address %s for MAC %s", record.IP, mac)
}

// A record whose row will not delete is skipped rather than aborting the
// sweep, so one wedged row cannot stop the rest. Caller holds p's lock.
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

// The only thing that walks p.declined, so the allocation path never pays for
// the scan: a quarantined address is a bit the allocator still has set, and is
// not offered until this runs. The caller must hold p's lock.
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

// The caller must hold p's lock.
func (p *pluginState) reclaim(t time.Time) int {
	return p.sweepExpired(t) + p.sweepDeclined(t)
}

func (p *pluginState) sweepOnce() {
	p.Lock()
	defer p.Unlock()
	if freed := p.reclaim(p.timeNow()); freed > 0 {
		log.Printf("Returned %d DHCPv4 address(es) to the pool", freed)
	}
}

// The loop lives for the lifetime of the process; p.stop is there for tests.
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

// Nothing in the server calls this; it keeps tests from leaking a goroutine.
func (p *pluginState) stopSweeper() {
	close(p.stop)
	<-p.done
}

// Half a lease, so an address is back in the pool well within one lease of
// lapsing.
func defaultSweepInterval(leaseTime time.Duration) time.Duration {
	if half := leaseTime / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// The count is uint64 rather than uint: a range covering the whole address
// space holds 2^32 addresses, which wraps to zero in uint on a 32-bit build.
func poolSize(start, end net.IP) uint64 {
	first := binary.BigEndian.Uint32(start.To4())
	last := binary.BigEndian.Uint32(end.To4())
	return uint64(last-first) + 1
}

// Floored at one address, so decline-probation still does something on a pool
// of two.
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

type pluginOptions struct {
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int
}

var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:      parseSweepInterval,
	declineArg:    parseDeclineProbation,
	declineMaxArg: parseDeclineMax,
}

// An unknown or repeated key is an error rather than quietly ignored: a typo
// must not leave the operator with a default they believe they overrode.
func parseOptions(leaseTime time.Duration, size uint64, extra []string) (pluginOptions, error) {
	opts := pluginOptions{
		sweepInterval:    defaultSweepInterval(leaseTime),
		declineProbation: defaultDeclineProbation,
		declineMax:       defaultDeclineMax(size),
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

// Zero is allowed and disables the quarantine; a negative value would read as
// "hold it back for a while" and do the opposite, so it is rejected.
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

// Zero is allowed and turns the quarantine off; a negative count is not.
func parseDeclineMax(opts *pluginOptions, raw string) error {
	count, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("invalid decline maximum %q: %w", raw, err)
	}
	if count < 0 {
		return fmt.Errorf("decline maximum cannot be negative, got: %v", raw)
	}
	opts.declineMax = count
	return nil
}

func setupRange(args ...string) (handler.Handler4, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Both come after everything that can fail: no goroutine sweeping a
	// half-built plugin, no half-built instance visible to a lease reader.
	p.startSweeper(p.sweepInterval)
	leases.Register(p)
	log.Printf("Serving %d addresses, reclaiming expired DHCPv4 leases every %s, declined addresses after %s, quarantining at most %d at a time",
		p.poolSize, p.sweepInterval, p.declineProbation, p.declineMax)
	return p.Handler4, nil
}

// The instance comes back idle -- storage open and leases re-allocated, but no
// sweeper -- so tests that own the goroutine's lifetime can call this directly.
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
