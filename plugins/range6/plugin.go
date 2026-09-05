// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package range6 implements a plugin that hands out DHCPv6 addresses from a
// pool, persisting the bindings in a sqlite database. It is the IA_NA
// counterpart of the range plugin; this fork could only delegate prefixes
// before.
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
// # Bindings
//
// A binding is keyed by the client DUID and the IAID of the IA_NA it came in
// on, which is the pair RFC 8415 uses to name one address association. One
// address per IA_NA and at most maxIANAs IA_NAs per message: a client with
// more interfaces than that gets the first few served and the rest ignored,
// which is cheaper than letting one packet drive an unbounded number of
// allocations.
//
// # What each message gets back
//
// SOLICIT and REQUEST allocate, or renew what this DUID and IAID already
// hold, and answer with the address (RFC 8415 §18.3.1 and §18.3.2). The server
// turns the response into an Advertise or, with Rapid Commit, a Reply, so the
// plugin fills in the IA_NA either way and persists on both: a client that
// takes what it was offered must find it still there.
//
// RENEW and REBIND extend the binding. A RENEW for a binding we do not have
// gets NoBinding (§18.3.4), a REBIND for one gets no IA_NA at all (§18.3.5):
// another server on the link may know the client, and answering would take
// the address away from it.
//
// CONFIRM asks whether the addresses a client woke up with still belong on
// this link. It gets one message-level status and changes no binding
// (§18.3.3).
//
// RELEASE frees what the client names, DECLINE quarantines it. Both answer per
// IA and carry a message-level Success (§18.3.7 and §18.3.8).
//
// INFORMATION-REQUEST is passed through untouched: it asks for configuration,
// not for an address.
//
// # Reclaiming addresses
//
// Bindings are reclaimed in two places: a background sweeper on a ticker, and
// lazily on the allocation path when the pool looks exhausted. Without either,
// expired bindings pile up in the map, the allocator and the database forever,
// and a stable population of churning clients eventually exhausts the pool
// permanently. A client that comes back after its binding lapsed but before
// anyone else took the address keeps it, because the expired address is handed
// to the allocator as a hint.
//
// # Declined addresses
//
// A DECLINE means the client found the address already in use on the link. The
// binding goes away, but the address stays out of the pool for the probation
// period so the next client does not walk into the same conflict. Quarantine
// is bounded twice over: by time, and by decline-max, because a client that
// declines everything it is offered would otherwise empty the pool one address
// at a time. When the quarantine is full, or when the pool is empty and there
// is nothing else left to reclaim, the address that has been held longest goes
// back first. None of this survives a restart: probation is tracked in memory
// only.
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
	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/allocators"
	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

var log = logger.GetLogger("plugins/range6")

// Plugin wraps plugin registration information. Address pools out of a
// start-end range only exist for DHCPv6 here; the DHCPv4 side is the range
// plugin.
var Plugin = plugins.Plugin{
	Name:   "range6",
	Setup6: setup6,
}

// newIPv6Allocator is bitmap.NewIPv6Allocator, extracted as a seam for tests.
// newPluginState already validates that both addresses parse as IPv6 and that
// first <= last before calling this, so through the public API the allocator
// can only fail on a range wider than a /96; overriding this var is how the
// remaining error paths are exercised deterministically.
var newIPv6Allocator = bitmap.NewIPv6Allocator

const (
	// sweepArg names the optional argument that overrides the background
	// sweep interval, e.g. "sweep:5m".
	sweepArg = "sweep"

	// declineArg names the optional argument that overrides how long a
	// declined address stays out of the pool, e.g. "decline-probation:1h".
	declineArg = "decline-probation"

	// declineMaxArg names the optional argument that overrides how many
	// declined addresses may be held back at once, e.g. "decline-max:32".
	declineMaxArg = "decline-max"

	// optionSyntax spells the optional arguments out for error messages.
	optionSyntax = sweepArg + ":<duration>, " + declineArg + ":<duration> or " + declineMaxArg + ":<count>"

	// minSweepInterval floors the derived sweep interval. A short lease time
	// must not turn the sweeper into a hot loop taking the plugin lock.
	minSweepInterval = 30 * time.Second

	// defaultDeclineProbation is what Kea uses for decline-probation-period.
	// A day is long enough that whatever was squatting on the address has
	// usually gone, and short enough that one bad afternoon does not bleed a
	// pool dry.
	defaultDeclineProbation = 24 * time.Hour

	// declineMaxDivisor sets the default quarantine bound to a tenth of the
	// pool, so declines can cost a tenth of the addresses at worst.
	declineMaxDivisor = 10

	// maxDUIDLen bounds the client DUID we are willing to key a binding by.
	// RFC 8415 §11.1 caps a DUID at 128 octets plus its two-octet type code,
	// so anything longer is malformed and is dropped rather than stored.
	maxDUIDLen = 130

	// maxIANAs bounds how many IA_NAs one message may drive. A DHCPv6 message
	// can carry any number of them, and each one costs an allocation, a row
	// and a map entry, so a single packet must not be able to ask for
	// thousands. Eight is well past what a real client with several
	// interfaces sends.
	maxIANAs = 8

	// maxHostnameLen is the RFC 1035 §2.3.4 limit on a domain name, and the
	// length we truncate a client-supplied name to before storing it.
	maxHostnameLen = 255

	// hostnameChars is the allow-list a client-supplied name is filtered
	// through. The name is only ever shown to an operator, so anything that
	// is not a domain character is dropped rather than escaped later.
	hostnameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
)

// Record holds one address binding: which client holds which address, until
// when, and the name the client asked to be known by.
type Record struct {
	DUID     []byte
	IAID     [4]byte
	IP       net.IP
	expires  int
	hostname string
}

// key returns the Records6 key for this binding.
func (r *Record) key() string {
	return leaseKey(r.DUID, r.IAID)
}

// expired reports whether the binding had already lapsed at t. Expiry is
// stored with second granularity, so a binding expiring exactly at t counts as
// expired.
func (r *Record) expired(t time.Time) bool {
	return int64(r.expires) <= t.Unix()
}

// leaseKey builds the map key for one address association. The IAID goes
// first because it is fixed width: with the variable-length DUID in front,
// two different clients could concatenate to the same key.
func leaseKey(duid []byte, iaid [4]byte) string {
	return string(iaid[:]) + string(duid)
}

// pluginState is the data held by an instance of the range6 plugin.
type pluginState struct {
	// Rough lock for the whole plugin, as in the range plugin.
	sync.Mutex
	// Records6 maps a client DUID and IAID to the address bound to it.
	Records6  map[string]*Record
	LeaseTime time.Duration
	leasedb   *sql.DB
	allocator allocators.Allocator

	// first and last are the bounds of the pool, kept for the CONFIRM
	// on-link test. Written during setup and read-only afterwards, both in
	// 16-byte form so they compare bytewise.
	first, last net.IP

	// name identifies this instance to a lease reader, poolRange spells the
	// configured range out for one, and poolSize is how many addresses it
	// holds. All three are built during setup and read-only afterwards; see
	// leases.go.
	name      string
	poolRange string
	poolSize  uint64

	// declined maps an address to the moment its probation ends. An entry
	// here has no binding and no database row, but its bit is still set in
	// the allocator, which is what actually keeps it out of circulation.
	// Guarded by the plugin lock, like Records6.
	declined map[string]time.Time

	// sweepInterval is how often the background sweeper reclaims expired
	// bindings, declineProbation how long a declined address is held back and
	// declineMax how many may be held at once. All set during setup and
	// read-only afterwards.
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int

	// now is the clock seam. It is written once during setup, before the
	// sweeper goroutine starts, and only read afterwards. Use timeNow rather
	// than calling it directly: a zero-valued pluginState (which the tests
	// build) leaves it nil.
	now func() time.Time

	// stop closes to shut the background sweeper down; done closes once it
	// has exited. The server never stops a plugin, so nothing closes stop in
	// production. It exists so tests can reap the goroutine deterministically
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

// messageHandlers dispatches on the message type. A type that is not in here,
// INFORMATION-REQUEST above all, is passed through untouched, which is also
// what keeps a message without a client ID from being rejected when it never
// needed one.
var messageHandlers = map[dhcpv6.MessageType]func(*pluginState, *dhcpv6.Message, dhcpv6.DHCPv6, []byte){
	dhcpv6.MessageTypeSolicit: (*pluginState).handleBind,
	dhcpv6.MessageTypeRequest: (*pluginState).handleBind,
	dhcpv6.MessageTypeRenew:   (*pluginState).handleRenew,
	dhcpv6.MessageTypeRebind:  (*pluginState).handleRebind,
	dhcpv6.MessageTypeConfirm: (*pluginState).handleConfirm,
	dhcpv6.MessageTypeRelease: (*pluginState).handleRelease,
	dhcpv6.MessageTypeDecline: (*pluginState).handleDecline,
}

// Handler6 handles DHCPv6 packets for the range6 plugin.
//
// Every message that gets this far is handed on rather than ending the chain,
// including RELEASE and DECLINE: the server sends a Reply for both, and the
// option plugins after this one still have to see the message. Only a packet
// we cannot make sense of at all is dropped.
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

// clientDUID returns the DUID the message is keyed by, reporting false when
// the packet has none or one too long to be a DUID at all.
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

// clientHostname reads the name the client asks to be known by, from the FQDN
// option of RFC 4704. It is stored with the binding so an operator can tell
// which client holds what; nothing in the plugin acts on it, and it is
// filtered and truncated first because it comes straight off the wire.
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

// limitIANAs caps how many IA_NAs of one message are answered. The rest are
// dropped silently as far as the client is concerned: an IA_NA with no answer
// is the same as one the server chose not to serve.
func limitIANAs(ianas []*dhcpv6.OptIANA) []*dhcpv6.OptIANA {
	if len(ianas) <= maxIANAs {
		return ianas
	}
	log.Debugf("Message carries %d IA_NAs, answering the first %d", len(ianas), maxIANAs)
	return ianas[:maxIANAs]
}

// eachIANA answers every IA_NA of the message under the plugin lock and adds
// what comes back to the response. An answer of nil adds nothing, which is how
// REBIND stays quiet about a binding it does not have.
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

// handleBind answers a SOLICIT or a REQUEST.
func (p *pluginState) handleBind(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.bind(duid, ia, hostname, now)
	})
}

// handleRenew answers a RENEW: the binding is extended, and an IAID we have
// nothing for gets NoBinding so the client stops asking us and starts over
// (RFC 8415 §18.3.4).
func (p *pluginState) handleRenew(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		if answer := p.extend(duid, ia, hostname, now); answer != nil {
			return answer
		}
		return statusIANA(ia.IaId, dhcpIana.StatusNoBinding, "no address bound to this IAID")
	})
}

// handleRebind answers a REBIND. Unlike a RENEW it is addressed to every
// server on the link, so an IAID we have nothing for is left to whichever
// server does (RFC 8415 §18.3.5).
func (p *pluginState) handleRebind(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	hostname := clientHostname(msg)
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.extend(duid, ia, hostname, now)
	})
}

// handleRelease frees the addresses a RELEASE names and answers per IA plus a
// message-level Success (RFC 8415 §18.3.7).
func (p *pluginState) handleRelease(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, _ time.Time) *dhcpv6.OptIANA {
		return p.releaseIANA(duid, ia)
	})
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "addresses released",
	})
}

// handleDecline takes the addresses a DECLINE reports as already in use out of
// circulation and answers per IA plus a message-level Success (RFC 8415
// §18.3.8).
func (p *pluginState) handleDecline(msg *dhcpv6.Message, resp dhcpv6.DHCPv6, duid []byte) {
	p.eachIANA(msg, resp, func(ia *dhcpv6.OptIANA, now time.Time) *dhcpv6.OptIANA {
		return p.declineIANA(duid, ia, now)
	})
	resp.AddOption(&dhcpv6.OptStatusCode{
		StatusCode:    dhcpIana.StatusSuccess,
		StatusMessage: "addresses declined",
	})
}

// handleConfirm answers a CONFIRM, which asks whether the addresses a client
// woke up with still belong on this link. The answer is one message-level
// status and no binding changes: a client that moved gets NotOnLink and starts
// over, one that is still here keeps what it has.
//
// A CONFIRM carrying no address at all is left alone. RFC 8415 §18.3.3 says
// the server must not reply to one, and adding no status is as close to that
// as a plugin in a chain gets.
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

// confirmedAddresses collects the addresses a CONFIRM lists, across the IA_NAs
// we are willing to look at.
func confirmedAddresses(msg *dhcpv6.Message) []net.IP {
	var addresses []net.IP
	for _, ia := range limitIANAs(msg.Options.IANA()) {
		for _, addr := range ia.Options.Addresses() {
			addresses = append(addresses, addr.IPv6Addr)
		}
	}
	return addresses
}

// onLink reports whether an address falls inside the pool. first and last are
// written during setup and never change, so this needs no lock.
func (p *pluginState) onLink(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	return bytes.Compare(v6, p.first) >= 0 && bytes.Compare(v6, p.last) <= 0
}

// bind answers one IA_NA of a SOLICIT or a REQUEST: it extends what this DUID
// and IAID already hold, or allocates an address for them. The caller must
// hold p's lock.
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

// extend answers one IA_NA of a RENEW or a REBIND, returning nil when this
// DUID and IAID hold nothing. The caller must hold p's lock.
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

// requestedAddress returns the address a client asks for in an IA_NA, or the
// zero net.IPNet when it names none. It is only ever a hint: the allocator
// honours it if the address is free and hands out something else if it is not.
func requestedAddress(ia *dhcpv6.OptIANA) net.IPNet {
	addresses := ia.Options.Addresses()
	if len(addresses) == 0 {
		return net.IPNet{}
	}
	return net.IPNet{IP: addresses[0].IPv6Addr}
}

// renewKnown extends the binding for key when there is one. found reports
// whether the client held one at all, which is what separates "no binding"
// from "nothing left to give". A nil record with found true means the binding
// had lapsed and the pool could not give the address back. The caller must
// hold p's lock.
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

// allocateLease hands a client a fresh address, persists it and tracks it in
// memory. hint is the zero net.IPNet for a binding we have never seen, the
// address the client asked for, or the one it held before its binding lapsed;
// the allocator honours a hint whenever that address is still free. A nil
// return means the pool is exhausted. The caller must hold p's lock.
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

// allocate asks the allocator for an address, and on failure reclaims what has
// lapsed and retries once. If nothing has lapsed either, the address that has
// been in quarantine longest goes back to the pool: an empty pool is a worse
// problem than the address conflict a client reported hours ago.
//
// The sweep is the O(len(Records6)) part of reclamation, so it deliberately
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
	if p.reclaim(p.timeNow()) == 0 && !p.evictOldestDeclined() {
		return net.IPNet{}, err
	}
	return p.allocator.Allocate(hint)
}

// reallocateExpired handles a client coming back after its binding lapsed but
// before the sweeper reclaimed it. The stale record is not served verbatim:
// the address goes back to the pool and is allocated again, hinting at the
// same address so a late client keeps it as long as nobody else has taken it.
// The caller must hold p's lock.
func (p *pluginState) reallocateExpired(key string, record *Record, hostname string, now time.Time) *Record {
	log.Debugf("Binding on %s for DUID %x IAID %x has expired, re-allocating", record.IP, record.DUID, record.IAID)
	hint := net.IPNet{IP: record.IP}
	if err := p.releaseLease(record); err != nil {
		log.Errorf("Could not reclaim the expired binding on %s: %v", record.IP, err)
		// The address is still spoken for somewhere (a row we failed to
		// delete, or an allocator that would not free it), so allocating
		// again could hand a second client the same address. Keep this client
		// where it is and let the next sweep retry.
		p.Records6[key] = record
		p.renew(record, hostname, now)
		return record
	}
	return p.allocateLease(key, record.DUID, record.IAID, hint, hostname, now)
}

// renew extends a binding so it outlives the lifetime we are about to
// advertise, and persists the change. A binding with enough time left is left
// untouched. The caller must hold p's lock.
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

// releaseLease returns a binding's address to the pool: it deletes the row
// from storage, drops the in-memory record, then frees the address in the
// allocator. Storage goes first on purpose. A binding we cannot forget on disk
// must not be handed to a second client, because a restart would reload the
// row and re-allocate the address to its original owner. The caller must hold
// p's lock.
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

// boundRecord returns the binding a RELEASE or a DECLINE names, or nil when
// this client holds none for the IAID or the IA lists an address it does not
// hold.
//
// RFC 8415 has the client name the addresses it is giving up, and that is the
// only thing tying the message to a binding. Going by the DUID alone would let
// anyone who can forge one empty the pool. The caller must hold p's lock.
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

// releaseIANA frees the address of one released IA_NA and builds the answer
// for it. The caller must hold p's lock.
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

// declineIANA quarantines the address of one declined IA_NA and builds the
// answer for it. The caller must hold p's lock.
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

// quarantine drops a declined binding and holds its address back from the pool
// for declineProbation.
//
// The client just told us the address is already in use on the link, so
// handing it to the next client would repeat the conflict. The record and the
// row go, but the allocator bit stays set, which is what keeps the address out
// of circulation; p.declined only records when it may come back. A probation
// of zero, or a bound of zero, skips all that and frees the address outright.
// The caller must hold p's lock.
func (p *pluginState) quarantine(record *Record, now time.Time) error {
	if p.declineProbation == 0 || p.declineMax == 0 {
		return p.releaseLease(record)
	}
	if err := p.freeIPAddress(record); err != nil {
		return fmt.Errorf("removing the declined binding from storage: %w", err)
	}
	delete(p.Records6, record.key())

	// One eviction is always enough: the map only ever grows by the single
	// entry added below, and declineMax is at least one here, so a full
	// quarantine is never empty.
	if len(p.declined) >= p.declineMax {
		p.evictOldestDeclined()
	}
	until := now.Add(p.declineProbation)
	p.declined[record.IP.String()] = until
	log.Printf("DUID %x declined %s, holding it back until %s", record.DUID, record.IP, until)
	return nil
}

// evictOldestDeclined returns the address that has been in quarantine longest
// to the pool, reporting whether there was one. Probation is the same length
// for every address, so the one whose probation ends first is also the one
// that has been held longest. The caller must hold p's lock.
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

// freeDeclined returns a quarantined address to the pool and forgets it.
//
// The entry goes even when the allocator refuses the address. Keeping it would
// wedge the quarantine at its bound forever, and an address the allocator says
// it is not holding is not coming back either way. The caller must hold p's
// lock.
func (p *pluginState) freeDeclined(ip string) {
	if err := p.allocator.Free(net.IPNet{IP: net.ParseIP(ip)}); err != nil {
		log.Errorf("Could not return the declined address %s to the pool: %v", ip, err)
	}
	delete(p.declined, ip)
}

// addressIANA builds the IA_NA answering a request with the bound address.
// T1 and T2 are the RFC 8415 §21.4 recommendation: renew halfway through the
// lifetime, rebind at 80% of it.
//
// The address is copied out of the record. The record stays in the map behind
// the plugin lock while the response goes on to the rest of the chain, and
// nothing after this point should be able to reach into it. The caller must
// hold p's lock.
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

// statusIANA builds an IA_NA carrying nothing but a status code, which is how
// RFC 8415 says no to one address association without failing the whole
// message.
func statusIANA(iaid [4]byte, code dhcpIana.StatusCode, message string) *dhcpv6.OptIANA {
	answer := &dhcpv6.OptIANA{IaId: iaid}
	answer.Options.Add(&dhcpv6.OptStatusCode{
		StatusCode:    code,
		StatusMessage: message,
	})
	return answer
}

// sweepExpired frees every binding that had expired at t and reports how many
// addresses went back to the pool. A record whose storage row cannot be
// deleted is logged and skipped rather than aborting the sweep, so one wedged
// row never stops the rest from being reclaimed. The caller must hold p's
// lock.
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

// sweepDeclined returns to the pool every address whose probation had ended at
// t, and reports how many.
//
// This is the only thing that walks p.declined on the timer. The allocation
// path must not pay for a map scan per client, and it does not have to: a
// quarantined address is simply a bit the allocator still has set, so it is
// never offered until this runs. The caller must hold p's lock.
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

// reclaim frees everything that is no longer spoken for at t: bindings that
// have expired, and declined addresses whose probation has ended. It reports
// how many addresses went back to the pool. The caller must hold p's lock.
func (p *pluginState) reclaim(t time.Time) int {
	return p.sweepExpired(t) + p.sweepDeclined(t)
}

// sweepOnce takes the lock and reclaims every expired binding and every
// declined address whose probation has run out.
func (p *pluginState) sweepOnce() {
	p.Lock()
	defer p.Unlock()
	if freed := p.reclaim(p.timeNow()); freed > 0 {
		log.Printf("Returned %d DHCPv6 address(es) to the pool", freed)
	}
}

// startSweeper runs the background reclamation loop. It lives for the lifetime
// of the process, since plugins are never stopped or unregistered, but it
// still honours p.stop so tests can shut it down.
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

// defaultDeclineMax holds back at most a tenth of the pool. A pool small
// enough that a tenth rounds to nothing still gets one slot, because the point
// of the quarantine is that the next client does not walk into the conflict
// the last one just reported.
func defaultDeclineMax(poolSize uint64) int {
	held := poolSize / declineMaxDivisor
	if held == 0 {
		return 1
	}
	// The allocator caps a pool at 2^32 addresses, so a tenth of one is well
	// within an int on every platform Go builds for.
	return int(held) //nolint:gosec // see above
}

// pluginOptions holds the settings taken from the optional key:value arguments
// that may follow the four positional ones.
type pluginOptions struct {
	sweepInterval    time.Duration
	declineProbation time.Duration
	declineMax       int
}

// optionParsers dispatches on the argument key. parseOptions handles ordering,
// duplicates and unknown keys for every entry here, so accepting another
// argument is one line plus its parser.
var optionParsers = map[string]func(*pluginOptions, string) error{
	sweepArg:      parseSweepInterval,
	declineArg:    parseDeclineProbation,
	declineMaxArg: parseDeclineMax,
}

// parseOptions reads the optional key:value arguments, which may come in any
// order. extra holds whatever followed the four required arguments. An unknown
// key, or a key given twice, is an error rather than something quietly
// ignored: a typo must not leave the operator with a default they believe they
// overrode.
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

// parseDeclineMax reads the value of a "decline-max:" argument. Zero is
// allowed and means no quarantine at all, the same as a probation of zero.
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

// parseIPv6 reads one of the two pool bounds. An IPv4 address is refused
// rather than mapped: a v4-mapped pool would build an allocator nothing on a
// DHCPv6 link can use.
func parseIPv6(arg string) (net.IP, error) {
	ip := net.ParseIP(arg)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %v", arg)
	}
	return ip.To16(), nil
}

// poolBounds parses and validates the first and last address of the pool.
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

// parseLeaseTime reads the fourth positional argument.
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

// setup6 builds the plugin instance and starts its background sweeper.
func setup6(args ...string) (handler.Handler6, error) {
	p, err := newPluginState(args...)
	if err != nil {
		return nil, err
	}
	// Started only once setup has fully succeeded: a failed setup must not
	// leave a goroutine behind sweeping a half-built plugin.
	p.startSweeper(p.sweepInterval)
	// Registered last, once everything that could fail has succeeded: a
	// reader must never find a half-built instance in the registry.
	leases.Register(p)
	log.Printf("Reclaiming expired DHCPv6 bindings every %s, declined addresses after %s (at most %d held back)",
		p.sweepInterval, p.declineProbation, p.declineMax)
	return p.Handler6, nil
}

// newPluginState validates the plugin arguments and builds a ready but idle
// instance: storage is open and the bindings are loaded and re-allocated, but
// no sweeper is running yet. setup6 starts it; tests that need to own the
// goroutine's lifetime call this directly.
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
		name:             "range6 " + filename,
		poolRange:        first.String() + "-" + last.String(),
		poolSize:         allocator.Size(),
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

// restore opens the lease database and puts every stored binding back where it
// was, both in the map and in the allocator.
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
		// A stored address outside today's pool is not refused by the
		// allocator, it is quietly replaced by one inside it, so the answer
		// has to be checked rather than the error alone.
		if !ip.IP.Equal(record.IP) {
			return fmt.Errorf("allocator did not re-allocate requested leased ip %v: %v", record.IP, ip.IP)
		}
	}
	return nil
}
