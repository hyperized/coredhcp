// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package range6 implements a plugin that hands out DHCPv6 addresses from a
// pool, persisting the bindings in a sqlite database. It is the IA_NA
// counterpart of the range plugin.
//
// Configure it with the lease database, the first and last address of the
// pool, and the lease time:
//
//	server6:
//	  plugins:
//	    - range6: leases6.sqlite3 2001:db8:1::100 2001:db8:1::1ff 12h
//
// Three optional arguments may follow, in any order:
//
//	sweep:<duration>              how often expired bindings are reclaimed in
//	                              the background. Defaults to half the lease
//	                              time, floored at 30s.
//	decline-probation:<duration>  how long an address a client declined is
//	                              held back from the pool. Defaults to 24h,
//	                              the same as Kea. 0 hands a declined address
//	                              straight back out.
//	decline-max:<count>           how many declined addresses may be held back
//	                              at once. Defaults to a tenth of the pool,
//	                              and never less than one address.
//
// A binding is keyed by the client DUID and the IAID of the IA_NA it came in
// on, RFC 8415's address-association pair (§18.3). RENEW on an unknown
// binding answers NoBinding, REBIND answers nothing so another server on the
// link can. CONFIRM changes no binding. Bindings are reclaimed by a
// background sweeper and lazily on allocation; a declined address is held
// out of the pool for decline-probation, capped by decline-max, and none of
// this survives a restart.
package range6

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

var log = logger.GetLogger("plugins/range6")

// Plugin wraps the range6 plugin registration information.
var Plugin = plugins.Plugin{
	Name:   "range6",
	Setup6: setup6,
}

// newIPv6Allocator is bitmap.NewIPv6Allocator, extracted as a seam for
// tests: overriding it exercises the allocator's error path deterministically.
var newIPv6Allocator = bitmap.NewIPv6Allocator

const (
	sweepArg = "sweep"

	declineArg = "decline-probation"

	declineMaxArg = "decline-max"

	// optionSyntax spells the optional arguments out for error messages.
	optionSyntax = sweepArg + ":<duration>, " + declineArg + ":<duration> or " + declineMaxArg + ":<count>"

	// Floors the derived sweep interval so a short lease time cannot turn
	// the sweeper into a hot loop holding the plugin lock.
	minSweepInterval = 30 * time.Second

	// Matches Kea's decline-probation-period default: long enough that a
	// squatter is usually gone, short enough that one bad afternoon does not
	// bleed the pool dry.
	defaultDeclineProbation = 24 * time.Hour

	declineMaxDivisor = 10

	// RFC 8415 §11.1 caps a DUID at 128 octets plus its 2-octet type code;
	// longer is malformed and dropped rather than stored.
	maxDUIDLen = 130

	// Caps IA_NAs per message so one packet cannot force unbounded
	// allocations; eight is well past what a real multi-interface client sends.
	maxIANAs = 8

	// RFC 1035 §2.3.4 domain-name length limit; client-supplied names are
	// truncated to it before storage.
	maxHostnameLen = 255

	// Client-supplied hostnames are filtered through this allow-list rather
	// than escaped, since they are only ever shown back to an operator.
	hostnameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
)

// Record holds one DHCPv6 address binding: client, address, expiry and hostname.
type Record struct {
	DUID     []byte
	IAID     [4]byte
	IP       net.IP
	expires  int
	hostname string
}

func (r *Record) key() string {
	return leaseKey(r.DUID, r.IAID)
}

// Expiry has second granularity; a binding expiring exactly at t counts as expired.
func (r *Record) expired(t time.Time) bool {
	return int64(r.expires) <= t.Unix()
}

// IAID goes first because it's fixed-width; with the variable-length DUID
// first, two different clients could concatenate to the same key.
func leaseKey(duid []byte, iaid [4]byte) string {
	return string(iaid[:]) + string(duid)
}

type pluginState struct {
	// Rough lock for the whole plugin, as in the range plugin.
	sync.Mutex
	// Records6 maps a client DUID and IAID to the address bound to it.
	Records6  map[string]*Record
	LeaseTime time.Duration
	leasedb   *sql.DB
	allocator allocators.Allocator

	// Bounds of the pool, for the CONFIRM on-link test. Written during
	// setup, read-only after, both in 16-byte form so they compare bytewise.
	first, last net.IP

	// Address to probation-end time. No binding or database row; the
	// allocator bit staying set is what keeps it out of circulation. Guarded
	// by the plugin lock, like Records6.
	declined map[string]time.Time

	// Set during setup, read-only afterwards.
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int

	// Clock seam, written once during setup before the sweeper starts and
	// read-only after. Use timeNow, not this directly: a zero-valued
	// pluginState (as tests build) leaves it nil.
	now func() time.Time

	// stop/done let the sweeper goroutine shut down deterministically. The
	// server never stops a plugin in production; this exists so tests don't
	// leak one per test.
	stop chan struct{}
	done chan struct{}
}

func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// Types not listed here, INFORMATION-REQUEST above all, pass through
// untouched — which also means a message without a client ID is not
// rejected when it never needed one.
var messageHandlers = map[dhcpv6.MessageType]func(*pluginState, *dhcpv6.Message, dhcpv6.DHCPv6, []byte){
	dhcpv6.MessageTypeSolicit: (*pluginState).handleBind,
	dhcpv6.MessageTypeRequest: (*pluginState).handleBind,
	dhcpv6.MessageTypeRenew:   (*pluginState).handleRenew,
	dhcpv6.MessageTypeRebind:  (*pluginState).handleRebind,
	dhcpv6.MessageTypeConfirm: (*pluginState).handleConfirm,
	dhcpv6.MessageTypeRelease: (*pluginState).handleRelease,
	dhcpv6.MessageTypeDecline: (*pluginState).handleDecline,
}

// Handler6 handles DHCPv6 packets for range6; only an unparsable packet is dropped, every other message (RELEASE and DECLINE included) is passed on down the chain.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("Could not decode the request: %v", err)
		return nil, true
	}

	handle, wanted := messageHandlers[msg.MessageType]
	if !wanted {
		return resp, false
	}

	duid, ok := clientDUID(msg)
	if !ok {
		return nil, true
	}

	handle(p, msg, resp, duid)
	return resp, false
}

func clientDUID(msg *dhcpv6.Message) ([]byte, bool) {
	client := msg.Options.ClientID()
	if client == nil {
		log.Error("Invalid packet received, no clientID")
		return nil, false
	}
	duid := client.ToBytes()
	if len(duid) > maxDUIDLen {
		log.Errorf("Dropping a request with a %d octet client DUID, the maximum is %d", len(duid), maxDUIDLen)
		return nil, false
	}
	return duid, true
}

// RFC 4704 FQDN option, stored only for operator visibility. Filtered and
// truncated first since it arrives straight off the wire.
func clientHostname(msg *dhcpv6.Message) string {
	fqdn := msg.Options.FQDN()
	if fqdn == nil || fqdn.DomainName == nil {
		return ""
	}
	name := strings.Map(func(r rune) rune {
		if strings.ContainsRune(hostnameChars, r) {
			return r
		}
		return -1
	}, strings.Join(fqdn.DomainName.Labels, "."))
	if len(name) > maxHostnameLen {
		return name[:maxHostnameLen]
	}
	return name
}

// Extra IA_NAs are dropped silently — an IA_NA with no answer already means
// the server chose not to serve it.
func limitIANAs(ianas []*dhcpv6.OptIANA) []*dhcpv6.OptIANA {
	if len(ianas) <= maxIANAs {
		return ianas
	}
	log.Debugf("Message carries %d IA_NAs, answering the first %d", len(ianas), maxIANAs)
	return ianas[:maxIANAs]
}

// A nil answer adds nothing to the response — this is how REBIND stays
// silent about a binding it doesn't have.
func (p *pluginState) eachIANA(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, answer func(*dhcpv6.OptIANA, time.Time) *dhcpv6.OptIANA) {
	p.Lock()
	defer p.Unlock()

	now := p.timeNow()
	for _, ia := range limitIANAs(msg.Options.IANA()) {
		if reply := answer(ia, now); reply != nil {
			resp.AddOption(reply)
		}
	}
}

func (p *pluginState) handleBind(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.bind(duid, ia, hostname, now)
	})
}

// RFC 8415 §18.3.4: an IAID with no binding gets NoBinding so the client
// stops retrying and starts over.
func (p *pluginState) handleRenew(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		if answer := p.extend(duid, ia, hostname, now); answer != nil {
			return answer
		}
		return statusIANA(ia.IaId, dhcpIana.StatusNoBinding, "no address bound to this IAID")
	})
}

// RFC 8415 §18.3.5: unlike RENEW, a REBIND goes to every server on the
// link, so an unknown IAID is left for whichever server has it.
func (p *pluginState) handleRebind(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.extend(duid, ia, hostname, now)
	})
}

// RFC 8415 §18.3.7.
func (p *pluginState) handleRelease(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, _ time.Time) *dhcpv6.OptIANA {
		return p.releaseIANA(duid, ia)
	})
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "addresses released",
	})
}

// RFC 8415 §18.3.8.
func (p *pluginState) handleDecline(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.declineIANA(duid, ia, now)
	})
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "addresses declined",
	})
}

// RFC 8415 §18.3.3: CONFIRM only reports on-link status, changing no
// binding. A CONFIRM naming no address gets no reply, as the RFC requires.
func (p *pluginState) handleConfirm(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, _ []byte) {
	addresses := confirmedAddresses(msg)
	if len(addresses) == 0 {
		log.Debug("Ignoring a CONFIRM that carries no address")
		return
	}
	for _, addr := range addresses {
		if p.onLink(addr) {
			continue
		}
		log.Debugf("CONFIRM names %s, which is not from this pool", addr)
		resp.AddOption(&dhcpv6.OptStatusCode{
			StatusCode:    dhcpIana.StatusNotOnLink,
			StatusMessage: "address is not from this pool",
		})
		return
	}
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "addresses are on link",
	})
}

func confirmedAddresses(msg *dhcpv6.Message) []net.IP {
	var addresses []net.IP
	for _, ia := range limitIANAs(msg.Options.IANA()) {
		for _, addr := range ia.Options.Addresses() {
			addresses = append(addresses, addr.IPv6Addr)
		}
	}
	return addresses
}

// No lock needed: first and last are written during setup and never change after.
func (p *pluginState) onLink(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	return bytes.Compare(v6, p.first) >= 0 && bytes.Compare(v6, p.last) <= 0
}

// The caller must hold p's lock.
func (p *pluginState) bind(duid []byte, ia *dhcpv6.OptIANA, hostname string, now time.Time) *dhcpv6.OptIANA {
	key := leaseKey(duid, ia.IaId)
	rec, found := p.renewKnown(key, hostname, now)
	if !found {
		log.Debugf("DUID %x IAID %x is new, leasing an IPv6 address", duid, ia.IaId)
		rec = p.allocateLease(key, duid, ia.IaId, requestedAddress(ia), hostname, now)
	}
	if rec == nil {
		return statusIANA(ia.IaId, dhcpIana.StatusNoAddrsAvail, "no address available in the pool")
	}
	return p.addressIANA(ia.IaId, rec)
}

// The caller must hold p's lock.
func (p *pluginState) extend(duid []byte, ia *dhcpv6.OptIANA, hostname string, now time.Time) *dhcpv6.OptIANA {
	rec, found := p.renewKnown(leaseKey(duid, ia.IaId), hostname, now)
	if !found {
		return nil
	}
	if rec == nil {
		return statusIANA(ia.IaId, dhcpIana.StatusNoAddrsAvail, "no address available in the pool")
	}
	return p.addressIANA(ia.IaId, rec)
}

// Only ever a hint: the allocator honours it if free, and picks something else otherwise.
func requestedAddress(ia *dhcpv6.OptIANA) net.IPNet {
	addresses := ia.Options.Addresses()
	if len(addresses) == 0 {
		return net.IPNet{}
	}
	return net.IPNet{IP: addresses[0].IPv6Addr}
}

// found distinguishes "no binding" from "nothing left to give": nil with
// found true means the binding lapsed and the pool couldn't reclaim it. The caller must hold p's lock.
func (p *pluginState) renewKnown(key, hostname string, now time.Time) (rec *Record, found bool) {
	known, ok := p.Records6[key]
	if !ok {
		return nil, false
	}
	if known.expired(now) {
		return p.reallocateExpired(key, known, hostname, now), true
	}
	p.renew(known, hostname, now)
	return known, true
}

// hint is zero, the client's requested address, or its pre-expiry address —
// honoured if still free. Nil return means the pool is exhausted. The caller must hold p's lock.
func (p *pluginState) allocateLease(key string, duid []byte, iaid [4]byte, hint net.IPNet, hostname string, now time.Time) *Record {
	ip, err := p.allocate(hint)
	if err != nil {
		log.Errorf("Could not allocate an address for DUID %x IAID %x: %v", duid, iaid, err)
		return nil
	}
	rec := &Record{
		DUID:     duid,
		IAID:     iaid,
		IP:       ip.IP,
		expires:  int(now.Add(p.LeaseTime).Round(time.Second).Unix()),
		hostname: hostname,
	}
	if err := p.saveIPAddress(rec); err != nil {
		log.Errorf("Could not persist the binding for DUID %x IAID %x: %v", duid, iaid, err)
	}
	p.Records6[key] = rec
	return rec
}

// On failure, reclaims expired bindings or the oldest quarantined address
// and retries once. Sweeping only here, rather than on every call, keeps an
// O(len(Records6)) scan off the path a boot storm hammers. The caller must hold p's lock.
func (p *pluginState) allocate(hint net.IPNet) (net.IPNet, error) {
	ip, err := p.allocator.Allocate(hint)
	if err == nil {
		return ip, nil
	}
	if p.reclaim(p.timeNow()) == 0 && !p.evictOldestDeclined() {
		return net.IPNet{}, err
	}
	return p.allocator.Allocate(hint)
}

// A late client's stale binding isn't served verbatim — the address is
// freed and reallocated with itself as the hint, so it keeps it unless
// someone else took it. The caller must hold p's lock.
func (p *pluginState) reallocateExpired(key string, record *Record, hostname string, now time.Time) *Record {
	log.Debugf("Binding on %s for DUID %x IAID %x has expired, re-allocating", record.IP, record.DUID, record.IAID)
	hint := net.IPNet{IP: record.IP}
	if err := p.releaseLease(record); err != nil {
		log.Errorf("Could not reclaim the expired binding on %s: %v", record.IP, err)
		// Still spoken for somewhere (a row we couldn't delete, or the
		// allocator held it) — allocating again could double-hand it, so
		// keep this client put for the next sweep.
		p.Records6[key] = record
		p.renew(record, hostname, now)
		return record
	}
	return p.allocateLease(key, record.DUID, record.IAID, hint, hostname, now)
}

// A binding with enough time left is left untouched. The caller must hold p's lock.
func (p *pluginState) renew(record *Record, hostname string, now time.Time) {
	if !time.Unix(int64(record.expires), 0).Before(now.Add(p.LeaseTime)) {
		return
	}
	record.expires = int(now.Add(p.LeaseTime).Round(time.Second).Unix())
	record.hostname = hostname
	if err := p.saveIPAddress(record); err != nil {
		log.Errorf("Could not persist the binding on %s: %v", record.IP, err)
	}
}

// Storage is deleted first on purpose: a binding still on disk must not be
// handed to a second client, since a restart would reload it and reclaim
// the address for its original owner. The caller must hold p's lock.
func (p *pluginState) releaseLease(record *Record) error {
	if err := p.freeIPAddress(record); err != nil {
		return fmt.Errorf("removing the binding from storage: %w", err)
	}
	delete(p.Records6, record.key())
	if err := p.allocator.Free(net.IPNet{IP: record.IP}); err != nil {
		return fmt.Errorf("freeing %s in the allocator: %w", record.IP, err)
	}
	return nil
}

// Matching by DUID alone would let anyone who can forge one empty the pool —
// RFC 8415 has the client name the address it's giving up, so that must
// match too. The caller must hold p's lock.
func (p *pluginState) boundRecord(duid []byte, ia *dhcpv6.OptIANA) *Record {
	record, ok := p.Records6[leaseKey(duid, ia.IaId)]
	if !ok {
		return nil
	}
	for _, addr := range ia.Options.Addresses() {
		if record.IP.Equal(addr.IPv6Addr) {
			return record
		}
	}
	return nil
}

// The caller must hold p's lock.
func (p *pluginState) releaseIANA(duid []byte, ia *dhcpv6.OptIANA) *dhcpv6.OptIANA {
	record := p.boundRecord(duid, ia)
	if record == nil {
		log.Debugf("Nothing to release for DUID %x IAID %x", duid, ia.IaId)
		return statusIANA(ia.IaId, dhcpIana.StatusNoBinding, "no such address bound to this IAID")
	}
	if err := p.releaseLease(record); err != nil {
		log.Errorf("Could not release %s for DUID %x: %v", record.IP, duid, err)
		return statusIANA(ia.IaId, dhcpIana.StatusUnspecFail, "could not release the address")
	}
	log.Printf("Released %s for DUID %x IAID %x", record.IP, duid, ia.IaId)
	return statusIANA(ia.IaId, dhcpIana.StatusSuccess, "address released")
}

// The caller must hold p's lock.
func (p *pluginState) declineIANA(duid []byte, ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
	record := p.boundRecord(duid, ia)
	if record == nil {
		log.Debugf("Nothing to decline for DUID %x IAID %x", duid, ia.IaId)
		return statusIANA(ia.IaId, dhcpIana.StatusNoBinding, "no such address bound to this IAID")
	}
	if err := p.quarantine(record, now); err != nil {
		log.Errorf("Could not quarantine %s for DUID %x: %v", record.IP, duid, err)
		return statusIANA(ia.IaId, dhcpIana.StatusUnspecFail, "could not decline the address")
	}
	return statusIANA(ia.IaId, dhcpIana.StatusSuccess, "address declined")
}

// The allocator bit stays set to keep the address out of circulation;
// p.declined only records when it may come back. Zero probation or zero
// bound skips quarantine and frees the address outright. The caller must hold p's lock.
func (p *pluginState) quarantine(record *Record, now time.Time) error {
	if p.declineProbation == 0 || p.declineMax == 0 {
		return p.releaseLease(record)
	}
	if err := p.freeIPAddress(record); err != nil {
		return fmt.Errorf("removing the declined binding from storage: %w", err)
	}
	delete(p.Records6, record.key())

	// One eviction is always enough: the map only grows by the single entry
	// added below, and declineMax is at least one here.
	if len(p.declined) >= p.declineMax {
		p.evictOldestDeclined()
	}
	until := now.Add(p.declineProbation)
	p.declined[record.IP.String()] = until
	log.Printf("DUID %x declined %s, holding it back until %s", record.DUID, record.IP, until)
	return nil
}

// Probation is the same length for every address, so the one whose
// probation ends first is also the one held longest. The caller must hold p's lock.
func (p *pluginState) evictOldestDeclined() bool {
	var (
		oldestIP string
		oldest   time.Time
	)
	for ip, until := range p.declined {
		if oldestIP == "" || until.Before(oldest) {
			oldestIP, oldest = ip, until
		}
	}
	if oldestIP == "" {
		return false
	}
	log.Printf("Returning %s to the pool before its probation ended", oldestIP)
	p.freeDeclined(oldestIP)
	return true
}

// The entry is dropped even if the allocator refuses the address — keeping
// it would wedge the quarantine at its bound forever, and it isn't coming
// back either way. The caller must hold p's lock.
func (p *pluginState) freeDeclined(ip string) {
	if err := p.allocator.Free(net.IPNet{IP: net.ParseIP(ip)}); err != nil {
		log.Errorf("Could not return the declined address %s to the pool: %v", ip, err)
	}
	delete(p.declined, ip)
}

// RFC 8415 §21.4: T1/T2 are half and 80% of the lifetime. The address is
// copied out since the record stays behind the lock while the response
// continues down the chain. The caller must hold p's lock.
func (p *pluginState) addressIANA(iaid [4]byte, record *Record) *dhcpv6.OptIANA {
	answer := &dhcpv6.OptIANA{
		IaId: iaid,
		T1:   p.LeaseTime / 2,
		T2:   p.LeaseTime * 4 / 5,
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, record.IP.To16())
	answer.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          ip,
		PreferredLifetime: p.LeaseTime,
		ValidLifetime:     p.LeaseTime,
	})
	return answer
}

// How RFC 8415 says no to one address association without failing the whole message.
func statusIANA(iaid [4]byte, code dhcpIana.StatusCode, message string) *dhcpv6.OptIANA {
	answer := &dhcpv6.OptIANA{IaId: iaid}
	answer.Options.Add(&dhcpv6.OptStatusCode{
		StatusCode:    code,
		StatusMessage: message,
	})
	return answer
}

// A row that can't be deleted is logged and skipped rather than aborting
// the sweep, so one wedged row doesn't block the rest. The caller must hold p's lock.
func (p *pluginState) sweepExpired(t time.Time) int {
	var freed int
	for _, record := range p.Records6 {
		if !record.expired(t) {
			continue
		}
		if err := p.releaseLease(record); err != nil {
			log.Errorf("Could not reclaim the expired binding on %s: %v", record.IP, err)
			continue
		}
		freed++
	}
	return freed
}

// The only thing that walks p.declined: a quarantined address is just a bit
// still set in the allocator, so the allocation path never pays for a
// per-client scan. The caller must hold p's lock.
func (p *pluginState) sweepDeclined(t time.Time) int {
	var freed int
	for ip, until := range p.declined {
		if until.After(t) {
			continue
		}
		p.freeDeclined(ip)
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
		log.Printf("Returned %d DHCPv6 address(es) to the pool", freed)
	}
}

// Lives for the process lifetime, since plugins are never stopped in
// production, but honours p.stop so tests can shut it down.
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

// Nothing in the server calls this; it exists so tests don't leak the sweeper goroutine.
func (p *pluginState) stopSweeper() {
	close(p.stop)
	<-p.done
}

// Half the lease time, so an address is back in the pool well within one
// lease of lapsing; floored at minSweepInterval.
func defaultSweepInterval(leaseTime time.Duration) time.Duration {
	if half := leaseTime / 2; half > minSweepInterval {
		return half
	}
	return minSweepInterval
}

// A pool small enough that a tenth rounds to zero still gets one slot — the
// point of quarantine is that the next client avoids the conflict just reported.
func defaultDeclineMax(poolSize uint64) int {
	held := poolSize / declineMaxDivisor
	if held == 0 {
		return 1
	}
	// The allocator caps a pool at 2^32 addresses, so this always fits in an int.
	return int(held) //nolint:gosec // see above
}

type pluginOptions struct {
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int
}

// parseOptions handles ordering, duplicates and unknown keys for every entry
// here, so a new argument is one line plus its parser.
var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:      parseSweepInterval,
	declineArg:    parseDeclineProbation,
	declineMaxArg: parseDeclineMax,
}

// Unknown or duplicate keys are errors rather than ignored, so a typo
// doesn't leave the operator believing they overrode a default.
func parseOptions(leaseTime time.Duration, poolSize uint64, extra []string) (pluginOptions, error) {
	opts := pluginOptions{
		sweepInterval:    defaultSweepInterval(leaseTime),
		declineProbation: defaultDeclineProbation,
		declineMax:       defaultDeclineMax(poolSize),
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

// Zero means no quarantine; negative is rejected since it would read as
// holding the address back while doing the opposite.
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

// Zero means no quarantine, same as a probation of zero.
func parseDeclineMax(opts *pluginOptions, raw string) error {
	held, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("invalid decline maximum %q: %w", raw, err)
	}
	if held < 0 {
		return fmt.Errorf("decline maximum cannot be negative, got: %v", raw)
	}
	opts.declineMax = held
	return nil
}

// IPv4 is refused rather than mapped — a v4-mapped pool would build an
// allocator nothing on a DHCPv6 link can use.
func parseIPv6(arg string) (net.IP, error) {
	ip := net.ParseIP(arg)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %v", arg)
	}
	return ip.To16(), nil
}

func poolBounds(firstArg, lastArg string) (first, last net.IP, err error) {
	if first, err = parseIPv6(firstArg); err != nil {
		return nil, nil, err
	}
	if last, err = parseIPv6(lastArg); err != nil {
		return nil, nil, err
	}
	if bytes.Compare(first, last) > 0 {
		return nil, nil, errors.New("start of IP range has to be lower than or equal to the end of an IP range")
	}
	return first, last, nil
}

func parseLeaseTime(arg string) (time.Duration, error) {
	leaseTime, err := time.ParseDuration(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid lease duration: %v", arg)
	}
	if leaseTime <= 0 {
		return 0, fmt.Errorf("lease duration has to be positive, got: %v", arg)
	}
	return leaseTime, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Started only after setup succeeds, so a failed setup can't leave a
	// goroutine sweeping a half-built plugin.
	p.startSweeper(p.sweepInterval)
	log.Printf("Reclaiming expired DHCPv6 bindings every %s, declined addresses after %s (at most %d held back)",
		p.sweepInterval, p.declineProbation, p.declineMax)
	return p.Handler6, nil
}

// Builds a ready but idle instance — no sweeper running yet; setup6 starts
// it, and tests that need to own the goroutine's lifetime call this directly.
func newPluginState(args ...string) (*pluginState, error) {
	if len(args) < 4 {
		return nil, fmt.Errorf("invalid number of arguments, want: 4 (file name, first address, last address, lease time), got: %d", len(args))
	}
	filename := args[0]
	if filename == "" {
		return nil, errors.New("file name cannot be empty")
	}

	first, last, err := poolBounds(args[1], args[2])
	if err != nil {
		return nil, err
	}
	allocator, err := newIPv6Allocator(first, last)
	if err != nil {
		return nil, fmt.Errorf("could not create an allocator: %w", err)
	}
	leaseTime, err := parseLeaseTime(args[3])
	if err != nil {
		return nil, err
	}
	opts, err := parseOptions(leaseTime, allocator.Size(), args[4:])
	if err != nil {
		return nil, err
	}

	p := &pluginState{
		LeaseTime:        leaseTime,
		allocator:        allocator,
		first:            first,
		last:             last,
		declined:         make(map[string]time.Time),
		sweepInterval:    opts.sweepInterval,
		declineProbation: opts.declineProbation,
		declineMax:       opts.declineMax,
		now:              time.Now,
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}
	if err := p.restore(filename); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pluginState) restore(filename string) error {
	if err := p.registerBackingDB(filename); err != nil {
		return fmt.Errorf("could not setup lease storage: %w", err)
	}
	records, err := loadRecords(p.leasedb)
	if err != nil {
		return fmt.Errorf("could not load records from file: %w", err)
	}
	p.Records6 = records
	log.Printf("Loaded %d DHCPv6 bindings from %s", len(records), filename)

	for _, record := range records {
		ip, err := p.allocator.Allocate(net.IPNet{IP: record.IP})
		if err != nil {
			return fmt.Errorf("failed to re-allocate leased ip %v: %w", record.IP, err)
		}
		// An address outside today's pool isn't refused by the allocator,
		// it's quietly replaced by one inside it — so the answer must be
		// checked, not just the error.
		if !ip.IP.Equal(record.IP) {
			return fmt.Errorf("allocator did not re-allocate requested leased ip %v: %v", record.IP, ip.IP)
		}
	}
	return nil
}
