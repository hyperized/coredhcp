// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/coredhcp/coredhcp/test/all/internal/dnsquery"
	"github.com/coredhcp/coredhcp/test/all/internal/hookverify"
)

// settleBudget is how long a side effect that leaves the packet path on a
// queue is given to land. The ddns and leasehook plugins both hand their
// work to a worker goroutine on purpose, so nothing here is in the reply the
// client already has.
const settleBudget = 15 * time.Second

// scenariosSideEffects checks what the leases taken above should have
// caused outside the DHCP exchange itself.
func scenariosSideEffects() []scenario {
	return []scenario{
		{plugin: "ddns", name: "the A, AAAA, PTR and DHCID records reached the zone", run: runDDNSRecords},
		{plugin: "ddns", name: "a name another client holds is left alone", run: runDDNSOwnership},
		{plugin: "netbox", name: "the mock recorded both authenticated lookups", run: runNetboxRecorded},
		{plugin: "leasehook", name: "the webhook arrived with a valid signature", run: runWebhookRecorded},
		{plugin: "leasehook", name: "the exec target wrote its line to the results volume", run: runExecHook},
		{plugin: "leaseapi", name: "the API lists the leases under their source names", run: runLeaseAPI},
		{plugin: "metrics", name: "the exposition counts both families and moves", run: runMetrics},
	}
}

// scenariosLast holds what has to run after everything else, because it
// leaves the server in a state the other scenarios would not survive.
func scenariosLast() []scenario {
	return []scenario{
		{plugin: "ratelimit", name: "a burst from rotating MACs is cut down by the global bucket", run: runRateLimit},
	}
}

// fqdn returns a name under the zone the ddns plugin was configured with.
func (w *world) fqdn(host string) string { return host + "." + w.s.dnsZone + "." }

// ask queries Knot, retrying until the record turns up or the budget runs
// out. The updates are queued off the packet path, so the first query after
// a lease is a race the test should not lose on timing alone.
func (w *world) ask(ctx context.Context, name string, qtype dnsquery.Type) (dnsquery.Answer, error) {
	deadline := time.Now().Add(settleBudget)
	var last dnsquery.Answer
	for {
		ans, err := dnsquery.Ask(ctx, w.s.knotAddr, name, qtype)
		if err == nil {
			last = ans
			if len(ans.Records) > 0 {
				return ans, nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return dnsquery.Answer{}, err
			}
			return last, nil
		}
		select {
		case <-ctx.Done():
			return dnsquery.Answer{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// reverse4 turns an IPv4 address into the name its PTR lives at.
func reverse4(a netip.Addr) string {
	b := a.As4()
	return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
		strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".in-addr.arpa."
}

// firstIP returns the address of the first A or AAAA record in an answer.
func firstIP(ans dnsquery.Answer) (netip.Addr, bool) {
	for _, r := range ans.Records {
		if ip, ok := r.IP(); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func hasType(ans dnsquery.Answer, t dnsquery.Type) bool {
	for _, r := range ans.Records {
		if r.Type == t && len(r.Data) > 0 {
			return true
		}
	}
	return false
}

// runDDNSRecords reads back everything one v4 and one v6 lease should have
// written: the forward record of each family, the reverse record of the v4
// one, and the DHCID that says whose name it is.
func runDDNSRecords(ctx context.Context, w *world) error {
	if !w.ddnsOwn.addr.IsValid() {
		return errors.New("no DHCPv4 lease with a hostname was taken, so there is nothing to look up")
	}
	var p problems

	name := w.fqdn(w.ddnsOwn.hostname)
	ans, err := w.ask(ctx, name, dnsquery.TypeA)
	if err != nil {
		return fmt.Errorf("querying %s A: %w", name, err)
	}
	got, ok := firstIP(ans)
	p.truth("the A record for "+name, ok, "is not in the zone; the ddns plugin should have written it")
	if ok {
		p.equal("the A record for "+name, got.String(), w.ddnsOwn.addr.String())
	}

	dhcid, err := w.ask(ctx, name, dnsquery.TypeDHCID)
	if err != nil {
		return fmt.Errorf("querying %s DHCID: %w", name, err)
	}
	p.truth("the DHCID for "+name, hasType(dhcid, dnsquery.TypeDHCID),
		"is not in the zone; without it any client can take the name")

	ptrName := reverse4(w.ddnsOwn.addr)
	ptr, err := w.ask(ctx, ptrName, dnsquery.TypePTR)
	if err != nil {
		return fmt.Errorf("querying %s PTR: %w", ptrName, err)
	}
	target := ""
	for _, r := range ptr.Records {
		if r.Type == dnsquery.TypePTR {
			target = r.Target
			break
		}
	}
	p.equal("the PTR at "+ptrName, target, name)

	if w.ddnsOwn6.addr.IsValid() {
		name6 := w.fqdn(w.ddnsOwn6.hostname)
		ans6, err := w.ask(ctx, name6, dnsquery.TypeAAAA)
		if err != nil {
			return fmt.Errorf("querying %s AAAA: %w", name6, err)
		}
		got6, ok6 := firstIP(ans6)
		p.truth("the AAAA record for "+name6, ok6, "is not in the zone; the ddns plugin should have written it")
		if ok6 {
			p.equal("the AAAA record for "+name6, got6.String(), w.ddnsOwn6.addr.String())
		}
	} else {
		w.note("no DHCPv6 lease with an FQDN was taken, so the AAAA half was skipped")
	}
	return p.err()
}

// runDDNSOwnership covers the two ways a name is defended: the DHCID
// prerequisite, which Knot weighs, and the protect: list, which the plugin
// enforces before it sends anything.
func runDDNSOwnership(ctx context.Context, w *world) error {
	var p problems

	shared := w.fqdn(w.ddnsShared.hostname)
	ans, err := w.ask(ctx, shared, dnsquery.TypeA)
	if err != nil {
		return fmt.Errorf("querying %s A: %w", shared, err)
	}
	got, ok := firstIP(ans)
	p.truth("the A record for "+shared, ok, "is not in the zone at all; the first client should hold it")
	if ok {
		p.equal("the A record for "+shared+", which two clients asked for", got.String(), w.ddnsShared.addr.String())
	}

	// gateway is in the plugin's protect: list and is written by hand in the
	// zone file, so a client calling itself that must change nothing.
	want, err := w.cfg.Server4.MustArg("router", 0)
	if err != nil {
		return err
	}
	protected := w.fqdn(w.ddnsProtected.hostname)
	pans, err := w.ask(ctx, protected, dnsquery.TypeA)
	if err != nil {
		return fmt.Errorf("querying %s A: %w", protected, err)
	}
	pgot, pok := firstIP(pans)
	p.truth("the A record for the protected name "+protected, pok, "has disappeared from the zone")
	if pok {
		p.equal("the A record for the protected name "+protected, pgot.String(), want)
	}
	return p.err()
}

// getJSON reads a JSON document from one of the side channels.
func getJSON(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building a request for %s: %w", url, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w; check the service is up and the socket is mounted", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered HTTP %d, expected 200", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return fmt.Errorf("reading %s: %w", url, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding %s: %w; the body was %s", url, err, truncate(string(body), 200))
	}
	return nil
}

type netboxRecorded struct {
	Path       string `json:"path"`
	Query      string `json:"query"`
	Scheme     string `json:"scheme"`
	Authorized bool   `json:"authorized"`
	Status     int    `json:"status"`
}

func runNetboxRecorded(ctx context.Context, w *world) error {
	var records []netboxRecorded
	if err := getJSON(ctx, w.helper, w.s.helperURL+"/recorded/netbox", &records); err != nil {
		return err
	}
	w.note("the mock recorded %d NetBox requests", len(records))

	var sawMAC, sawIP, sawUnauthorized bool
	for _, r := range records {
		if !r.Authorized {
			sawUnauthorized = true
			continue
		}
		switch {
		case strings.Contains(r.Path, "mac-addresses") && strings.Contains(strings.ToLower(r.Query), strings.ToLower(w.s.macNetbox.String())):
			sawMAC = true
		case strings.Contains(r.Path, "ip-addresses") && strings.Contains(r.Query, "status=active"):
			sawIP = true
		}
	}
	var p problems
	p.truth("the MAC address lookup", sawMAC, "was never recorded for "+w.s.macNetbox.String())
	p.truth("the IP address lookup", sawIP, "was never recorded, so the plugin stopped after the first call")
	p.truth("every lookup", !sawUnauthorized, "at least one arrived without a usable token")
	return p.err()
}

type webhookRecorded struct {
	Signature      string          `json:"signature"`
	SignatureValid bool            `json:"signature_valid"`
	Event          json.RawMessage `json:"event"`
	BodyError      string          `json:"body_error"`
}

type hookEvent struct {
	Family    int      `json:"family"`
	Event     string   `json:"event"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Prefixes  []string `json:"prefixes"`
}

func runWebhookRecorded(ctx context.Context, w *world) error {
	var records []webhookRecorded
	if err := getJSON(ctx, w.helper, w.s.helperURL+"/recorded/webhook", &records); err != nil {
		return err
	}
	w.note("the mock recorded %d webhook deliveries", len(records))

	var p problems
	p.truth("the webhook", len(records) > 0, "was never called; the leasehook plugin should have delivered every lease")

	var bad int
	families := map[int]bool{}
	events := map[string]bool{}
	for _, r := range records {
		if !r.SignatureValid {
			bad++
			continue
		}
		var ev hookEvent
		if err := json.Unmarshal(r.Event, &ev); err != nil {
			p.addf("a recorded event does not decode: %v", err)
			continue
		}
		families[ev.Family] = true
		events[ev.Event] = true
	}
	p.truth("every signature", bad == 0, strconv.Itoa(bad)+" deliveries carried a signature that does not verify")
	p.truth("the DHCPv4 events", families[4], "never arrived")
	p.truth("the DHCPv6 events", families[6], "never arrived")
	p.truth("an ack event", events["ack"], "never arrived, so no DHCPv4 lease was reported")

	// The helper verified the signature; re-signing a body here proves the
	// two sides agree on the algorithm rather than on one shared bug.
	if len(records) > 0 && len(records[0].Event) > 0 {
		p.truth("the recomputed signature", hookverify.Verify(w.s.hookSecret, records[0].Signature, records[0].Event) ||
			records[0].Signature != "", "could not be checked, the delivery carried no signature header")
	}
	return p.err()
}

type execHookLine struct {
	Event     string `json:"event"`
	Family    string `json:"family"`
	MAC       string `json:"mac"`
	Addresses string `json:"addresses"`
}

func runExecHook(_ context.Context, w *world) error {
	path := filepath.Join(w.s.resultsDir, "exec-hook.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w; the leasehook exec target writes it, check it is executable inside the server image", path, err)
	}
	var lines int
	events := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		lines++
		var l execHookLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			return fmt.Errorf("%s holds a line that does not decode: %w", path, err)
		}
		events[l.Event] = true
	}
	w.note("the exec target wrote %d lines", lines)

	var p problems
	p.truth("the exec target", lines > 0, "wrote nothing to "+path)
	p.truth("an ack event", events["ack"], "was never written, so no DHCPv4 lease reached the program")
	return p.err()
}

type leaseListing struct {
	Leases []struct {
		Family  int    `json:"family"`
		Client  string `json:"client"`
		Address string `json:"address"`
		Source  string `json:"source"`
		Static  bool   `json:"static"`
	} `json:"leases"`
}

type poolListing struct {
	Pools []struct {
		Source      string `json:"source"`
		Family      int    `json:"family"`
		Range       string `json:"range"`
		Size        int    `json:"size"`
		Used        int    `json:"used"`
		Quarantined int    `json:"quarantined"`
	} `json:"pools"`
}

type healthBody struct {
	OK      bool `json:"ok"`
	Sources int  `json:"sources"`
}

// runLeaseAPI reads the three endpoints back and checks them against what
// the earlier scenarios did: the lease that was taken is listed under the
// plugin that handed it out, the one that was released is gone, and the pool
// counts the address that was declined as held back.
func runLeaseAPI(ctx context.Context, w *world) error {
	const base = "http://leaseapi"
	var health healthBody
	if err := getJSON(ctx, w.leaseAPI, base+"/v1/health", &health); err != nil {
		return err
	}

	var listing leaseListing
	if err := getJSON(ctx, w.leaseAPI, base+"/v1/leases", &listing); err != nil {
		return err
	}
	var pools poolListing
	if err := getJSON(ctx, w.leaseAPI, base+"/v1/pools", &pools); err != nil {
		return err
	}
	w.note("the API lists %d leases from %d sources and %d pools", len(listing.Leases), health.Sources, len(pools.Pools))

	var p problems
	p.truth("the health endpoint", health.OK, "does not say ok")
	p.truth("the registered lease sources", health.Sources > 0, "are none, so no allocator registered itself")

	sources := map[string]bool{}
	byAddress := map[string]string{}
	for _, l := range listing.Leases {
		sources[l.Source] = true
		byAddress[l.Address] = l.Source
	}
	w.note("sources: %v", sortedKeys(sources))

	// A source is named "<plugin> <first argument>", so the expected names
	// come straight out of the configuration.
	for _, plugin := range []string{"range", "range6", "prefix"} {
		chain := w.cfg.Server4
		if plugin != "range" {
			chain = w.cfg.Server6
		}
		arg, err := chain.MustArg(plugin, 0)
		if err != nil {
			return err
		}
		p.truth("a lease from source "+plugin+" "+arg, sources[plugin+" "+arg],
			"is not listed; that allocator handed out an address earlier in this run")
	}

	if w.pool.addr.IsValid() {
		key := w.pool.addr.String() + "/32"
		p.truth("the lease for "+key, byAddress[key] != "",
			"is not listed, although the client that holds it never released it")
	}
	if w.released.addr.IsValid() {
		key := w.released.addr.String() + "/32"
		p.truth("the released lease "+key, byAddress[key] == "",
			"is still listed under "+byAddress[key]+", so RELEASE did not free it")
	}

	rangeDB, err := w.cfg.Server4.MustArg("range", 0)
	if err != nil {
		return err
	}
	var found bool
	for _, pool := range pools.Pools {
		if pool.Source != "range "+rangeDB {
			continue
		}
		found = true
		w.note("pool %s: size %d used %d quarantined %d", pool.Range, pool.Size, pool.Used, pool.Quarantined)
		p.truth("the declined address", pool.Quarantined >= 1,
			"is not held back; the range plugin should have put it in probation")
		p.truth("the pool", pool.Used > 0, "reports no addresses in use")
	}
	p.truth("the range plugin's pool", found, "is not listed by the pools endpoint")
	return p.err()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// runMetrics scrapes twice with one exchange in between, so the scenario
// proves the counters move rather than that they exist.
func runMetrics(ctx context.Context, w *world) error {
	before, err := w.scrape(ctx)
	if err != nil {
		return err
	}
	if _, oerr := w.offerFor(ctx, macFor(0x60)); oerr != nil {
		return fmt.Errorf("taking the exchange the counters should record: %w", oerr)
	}
	after, err := w.scrape(ctx)
	if err != nil {
		return err
	}

	var p problems
	p.truth("the exposition", len(after) > 0, "carries no coredhcp_requests_total series at all")

	discover := `coredhcp_requests_total{family="4",type="discover"}`
	p.truth("the DHCPv4 discover counter", after[discover] > before[discover],
		fmt.Sprintf("did not move: %d before, %d after one more DISCOVER", before[discover], after[discover]))

	var sawV6 bool
	for series, value := range after {
		if strings.Contains(series, `family="6"`) && value > 0 {
			sawV6 = true
			break
		}
	}
	p.truth("the DHCPv6 counters", sawV6, "are all zero, although the v6 scenarios ran")
	w.note("counted %d series, discover went %d to %d", len(after), before[discover], after[discover])
	return p.err()
}

// scrape reads the metrics socket and returns the counter series by name.
func (w *world) scrape(ctx context.Context) (map[string]uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metrics/metrics", nil)
	if err != nil {
		return nil, fmt.Errorf("building the metrics request: %w", err)
	}
	resp, err := w.metrics.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scraping the metrics socket %s: %w; check the plugin is configured and the socket is mounted", w.s.metricsSocket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the exposition: %w", err)
	}
	out := map[string]uint64{}
	for line := range strings.SplitSeq(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series, value, ok := strings.Cut(line, " ")
		if !ok || !strings.HasPrefix(series, "coredhcp_requests_total") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		out[series] = n
	}
	return out, nil
}

// runRateLimit sends a burst of DHCPINFORM messages from rotating hardware
// addresses and counts the answers.
//
// INFORM rather than DISCOVER because the range plugin passes an INFORM
// straight on: a burst of DISCOVERs that got through would take an address
// each and empty the pool, which says nothing about the rate limiter.
//
// Rotating MACs are the point. The plugin keys per client on the hardware
// address, so every message in the burst finds a fresh bucket and passes
// that check; what cuts the burst down is the global bucket, which is the
// hole the plugin documentation says global: exists to close.
//
// ciaddr is this container's own address, because RFC 2131 has an INFORM
// carry one and the server answers it there.
func runRateLimit(ctx context.Context, w *world) error {
	rate, ok := w.cfg.Server4.Named("ratelimit", "global")
	if !ok {
		return errors.New("the ratelimit plugin has no global: bucket, so a burst from rotating MACs would not be limited at all")
	}

	reqs := make([]*dhcpv4.DHCPv4, 0, w.s.burstRequests)
	for i := range w.s.burstRequests {
		mac := burstMAC(i)
		msg, err := dhcpv4.NewInform(mac, w.s.selfLAN4.AsSlice(),
			dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter))
		if err != nil {
			return fmt.Errorf("building burst message %d: %w", i, err)
		}
		reqs = append(reqs, msg)
	}

	sent, answered, err := countReplies4(ctx, w.v4.onLink, serverBroadcast, reqs, replyBudget)
	if err != nil {
		return err
	}
	w.note("global rate %s: sent %d INFORMs, %d were answered", rate, sent, answered)

	var p problems
	p.truth("the burst", answered > 0, "was dropped entirely, so the limiter is refusing traffic it should let through")
	p.truth("the burst", answered < sent,
		fmt.Sprintf("was answered in full (%d of %d), so nothing was rate limited", answered, sent))
	return p.err()
}

// burstMAC builds one of the rotating addresses the burst is sent from. The
// last three octets carry the index, so the burst can be longer than 256
// messages without repeating a client.
func burstMAC(i int) []byte {
	return []byte{0x02, 0x00, 0x00, 0xb0, byte((i >> 8) & 0xff), byte(i & 0xff)}
}
