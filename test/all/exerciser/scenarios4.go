// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

// wpadOption is the site-local code the options plugin is configured with.
const wpadOption = dhcpv4.GenericOptionCode(252)

// defaultPRL is the parameter request list every DHCPv4 client here sends.
//
// Several plugins only write their option when the client asked for it: dns
// and bootfile do, and ipv6only acts only on a request for option 108, which
// is deliberately left out of this list so that the ordinary scenarios still
// get an address.
var defaultPRL = []dhcpv4.OptionCode{
	dhcpv4.OptionSubnetMask,
	dhcpv4.OptionRouter,
	dhcpv4.OptionDomainNameServer,
	dhcpv4.OptionHostName,
	dhcpv4.OptionInterfaceMTU,
	dhcpv4.OptionNTPServers,
	dhcpv4.OptionIPAddressLeaseTime,
	dhcpv4.OptionServerIdentifier,
	dhcpv4.OptionTFTPServerName,
	dhcpv4.OptionBootfileName,
	dhcpv4.OptionDNSDomainSearchList,
	dhcpv4.OptionClasslessStaticRoute,
	wpadOption,
}

// discover builds an on-link DISCOVER.
//
// Two things are on every message rather than per scenario. The broadcast
// flag, because the reply to a client with no address otherwise leaves as a
// layer 2 unicast to a MAC address this container does not own, and the
// autoconfigure option, because the autoconfigure plugin sits ahead of the
// allocators and RFC 2563 section 2.3 has it drop a DISCOVER that does not
// carry one. See the chain comment in config/config.yml.tmpl.
func discover(mac net.HardwareAddr, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
	base := []dhcpv4.Modifier{
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithRequestedOptions(defaultPRL...),
		dhcpv4.WithOption(dhcpv4.OptAutoConfigure(dhcpv4.AutoConfigure)),
	}
	msg, err := dhcpv4.NewDiscovery(mac, append(base, mods...)...)
	if err != nil {
		return nil, fmt.Errorf("building a DISCOVER for %s: %w", mac, err)
	}
	return msg, nil
}

// offerFor runs one DISCOVER and returns the OFFER.
func (w *world) offerFor(ctx context.Context, mac net.HardwareAddr, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
	msg, err := discover(mac, mods...)
	if err != nil {
		return nil, err
	}
	return exchange4(ctx, w.v4.onLink, serverBroadcast, msg, isReplyTo(msg, dhcpv4.MessageTypeOffer), replyBudget)
}

// leaseFor runs a full DISCOVER and REQUEST and returns the ACK.
func (w *world) leaseFor(ctx context.Context, mac net.HardwareAddr, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
	offer, err := w.offerFor(ctx, mac, mods...)
	if err != nil {
		return nil, err
	}
	// The library gives a REQUEST a parameter request list of four codes,
	// so the full one has to be put back: every plugin that honours the list
	// would otherwise leave its option out of the ACK.
	req, err := dhcpv4.NewRequestFromOffer(offer, append([]dhcpv4.Modifier{
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithRequestedOptions(defaultPRL...),
	}, mods...)...)
	if err != nil {
		return nil, fmt.Errorf("building a REQUEST from the offer for %s: %w", mac, err)
	}
	ack, err := exchange4(ctx, w.v4.onLink, serverBroadcast, req, isReplyTo(req, dhcpv4.MessageTypeAck), replyBudget)
	if err != nil {
		return nil, err
	}
	if !ack.YourIPAddr.Equal(offer.YourIPAddr) {
		return nil, fmt.Errorf("the ACK carries %s where the OFFER carried %s", ack.YourIPAddr, offer.YourIPAddr)
	}
	return ack, nil
}

// scenarios4 is the on-link DHCPv4 table.
//
//nolint:funlen // one table entry per plugin, which is the point of the file
func scenarios4() []scenario {
	return []scenario{
		{
			plugin: "range",
			name:   "a fresh client gets an address out of the configured pool",
			run:    runRange4,
		},
		{plugin: "dns", name: "option 6 carries the configured resolvers", run: optionCheck("dns", checkDNS)},
		{plugin: "router", name: "option 3 carries the configured gateway", run: optionCheck("router", checkRouter)},
		{plugin: "netmask", name: "option 1 carries the configured mask", run: optionCheck("netmask", checkNetmask)},
		{plugin: "mtu", name: "option 26 carries the configured MTU", run: optionCheck("mtu", checkMTU)},
		{plugin: "ntp", name: "option 42 carries the configured NTP servers", run: optionCheck("ntp", checkNTP)},
		{plugin: "searchdomains", name: "option 119 carries the configured search list", run: optionCheck("searchdomains", checkSearch)},
		{plugin: "staticroute", name: "option 121 carries the configured route", run: optionCheck("staticroute", checkStaticRoute)},
		{plugin: "options", name: "the generic option 252 is set unconditionally", run: optionCheck("options", checkGenericOption)},
		{plugin: "leasetime", name: "option 51 carries the configured lease time", run: optionCheck("lease_time", checkLeaseTime)},
		{plugin: "serverid", name: "option 54 carries the configured server identifier", run: optionCheck("server_id", checkServerID)},
		{
			plugin: "bootfile",
			name:   "two client architectures get two different boot files",
			run:    runBootfile,
		},
		{
			plugin: "autoconfigure",
			name:   "option 116 is answered, and a DISCOVER without one is dropped",
			run:    runAutoconfigure,
		},
		{
			plugin: "ipv6only",
			name:   "option 108 appears only for a client that asked, and ends the chain",
			run:    runIPv6Only,
		},
		{
			plugin: "file",
			name:   "a MAC in the static lease file gets exactly that address",
			run:    runFile4,
		},
		{
			plugin: "netbox",
			name:   "a MAC NetBox documents gets the address on its interface",
			run:    runNetbox4,
		},
		{
			plugin: "redis",
			name:   "a MAC with a hash in Redis gets the address it holds",
			run:    runRedis4,
		},
		{
			plugin: "macfilter",
			name:   "a MAC on the deny list gets no answer at all",
			run:    runMacfilter4,
		},
		{
			plugin: "serverid",
			name:   "a REQUEST naming another server is ignored",
			run:    runForeignServerID,
		},
		{
			plugin: "range",
			name:   "RELEASE frees the address and DECLINE quarantines one",
			run:    runReleaseDecline,
		},
		{
			plugin: "ddns",
			name:   "two clients claim one hostname and three claim their own",
			run:    runDDNSLeases,
		},
	}
}

// runRange4 takes the first ordinary lease of the run and keeps it for the
// scenarios that read it back out of the lease API.
func runRange4(ctx context.Context, w *world) error {
	mac := macFor(0x30)
	ack, err := w.leaseFor(ctx, mac, dhcpv4.WithOption(dhcpv4.OptHostName("pool-client")))
	if err != nil {
		return err
	}
	pool, err := poolFromConfig(w)
	if err != nil {
		return err
	}
	got := toAddr(ack.YourIPAddr)
	w.note("offered %s from pool %s", got, pool)
	var p problems
	p.truth("the leased address", pool.contains(got), fmt.Sprintf("%s is outside the pool %s the range plugin is configured with", got, pool))
	w.pool = leaseFact{mac: mac, addr: got, hostname: "pool-client"}
	return p.err()
}

// poolFromConfig reads the range plugin's pool out of the server's own
// configuration: `- range: <db> <first> <last> <lease> [options]`.
func poolFromConfig(w *world) (addrRange, error) {
	first, err := w.cfg.Server4.MustArg("range", 1)
	if err != nil {
		return addrRange{}, err
	}
	last, err := w.cfg.Server4.MustArg("range", 2)
	if err != nil {
		return addrRange{}, err
	}
	f, err1 := netip.ParseAddr(first)
	l, err2 := netip.ParseAddr(last)
	if err := join(err1, err2); err != nil {
		return addrRange{}, fmt.Errorf("the range plugin's pool does not parse: %w", err)
	}
	return addrRange{first: f, last: l}, nil
}

// optionCheck turns a single-option assertion into a scenario. Each one
// takes a fresh lease rather than reusing one, so an option that is only set
// on the ACK or only on the OFFER cannot hide behind another scenario's
// message.
func optionCheck(plugin string, check func(*world, *dhcpv4.DHCPv4, *problems) error) func(context.Context, *world) error {
	return func(ctx context.Context, w *world) error {
		if !w.cfg.Server4.Has(plugin) {
			return fmt.Errorf("the server4 chain does not list %q; this scenario has nothing to prove", plugin)
		}
		ack, err := w.leaseFor(ctx, macFor(0x31))
		if err != nil {
			return err
		}
		var p problems
		if err := check(w, ack, &p); err != nil {
			return err
		}
		return p.err()
	}
}

func checkDNS(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	args, _ := w.cfg.Server4.First("dns")
	p.equal("option 6 (dns)", ipsToString(ack.DNS()), argsToString(args))
	return nil
}

func checkRouter(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	args, _ := w.cfg.Server4.First("router")
	p.equal("option 3 (router)", ipsToString(ack.Router()), argsToString(args))
	return nil
}

func checkNetmask(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	want, err := w.cfg.Server4.MustArg("netmask", 0)
	if err != nil {
		return err
	}
	mask := ack.SubnetMask()
	got := ""
	if len(mask) > 0 {
		got = net.IP(mask).String()
	}
	p.equal("option 1 (subnet mask)", got, want)
	return nil
}

func checkMTU(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	want, err := w.cfg.Server4.MustArg("mtu", 0)
	if err != nil {
		return err
	}
	raw := ack.Options.Get(dhcpv4.OptionInterfaceMTU)
	if len(raw) != 2 {
		p.addf("option 26 (mtu) is %d bytes, expected two", len(raw))
		return nil
	}
	p.equal("option 26 (mtu)", strconv.Itoa(int(raw[0])<<8|int(raw[1])), want)
	return nil
}

func checkNTP(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	args, _ := w.cfg.Server4.First("ntp")
	p.equal("option 42 (ntp)", ipsToString(ack.NTPServers()), argsToString(args))
	return nil
}

func checkSearch(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	args, _ := w.cfg.Server4.First("searchdomains")
	got := ""
	if labels := ack.DomainSearch(); labels != nil {
		got = argsToString(labels.Labels)
	}
	p.equal("option 119 (domain search)", got, argsToString(args))
	return nil
}

func checkStaticRoute(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	args, _ := w.cfg.Server4.First("staticroute")
	routes := ack.ClasslessStaticRoute()
	got := make([]string, 0, len(routes))
	for _, r := range routes {
		got = append(got, r.Dest.String()+","+normalizeIP(r.Router))
	}
	p.equal("option 121 (classless static route)", argsToString(got), argsToString(args))
	return nil
}

func checkGenericOption(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	arg, err := w.cfg.Server4.MustArg("options", 0)
	if err != nil {
		return err
	}
	// The argument is code:type:value, split on the first two colons only,
	// because a URL value holds colons of its own.
	code, rest, ok1 := cut(arg, ":")
	_, want, ok2 := cut(rest, ":")
	if !ok1 || !ok2 {
		return fmt.Errorf("the options plugin argument %q is not code:type:value", arg)
	}
	if code != strconv.Itoa(int(wpadOption)) {
		return fmt.Errorf("the options plugin is configured for code %s, this scenario asserts code %d", code, wpadOption)
	}
	p.equal("option "+code, string(ack.Options.Get(wpadOption)), want)
	return nil
}

func checkLeaseTime(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	arg, err := w.cfg.Server4.MustArg("lease_time", 0)
	if err != nil {
		return err
	}
	want, err := time.ParseDuration(arg)
	if err != nil {
		return fmt.Errorf("the configured lease time %q is not a duration: %w", arg, err)
	}
	p.equal("option 51 (lease time)", ack.IPAddressLeaseTime(0).String(), want.String())
	return nil
}

func checkServerID(w *world, ack *dhcpv4.DHCPv4, p *problems) error {
	want, err := w.cfg.Server4.MustArg("server_id", 0)
	if err != nil {
		return err
	}
	p.equal("option 54 (server identifier)", normalizeIP(ack.ServerIdentifier()), want)
	return nil
}

// runBootfile sends two DISCOVERs that differ only in the architecture they
// claim, and asserts the two boot files the plugin is configured with.
func runBootfile(ctx context.Context, w *world) error {
	args, ok := w.cfg.Server4.First("bootfile")
	if !ok {
		return errors.New("the server4 chain does not list bootfile")
	}
	want := map[string]string{}
	for _, a := range args {
		if k, v, found := cut(a, "="); found {
			want[k] = v
		}
	}

	var p problems
	for _, tc := range []struct {
		key  string
		arch iana.Arch
		mac  byte
	}{
		{key: "x86-bios", arch: iana.INTEL_X86PC, mac: 0x32},
		{key: "x86-64-uefi", arch: iana.EFI_X86_64, mac: 0x33},
	} {
		url, ok := want[tc.key]
		if !ok {
			p.addf("the bootfile plugin has no %s entry, so this scenario cannot assert one", tc.key)
			continue
		}
		offer, err := w.offerFor(ctx, macFor(tc.mac), dhcpv4.WithOption(dhcpv4.OptClientArch(tc.arch)))
		if err != nil {
			return fmt.Errorf("architecture %s: %w", tc.key, err)
		}
		// The plugin splits a tftp URL into the server name in option 66 and
		// the path in option 67, so the two halves are compared against the
		// URL the configuration spells.
		got := "tftp://" + offer.TFTPServerName() + offer.BootFileNameOption()
		w.note("architecture %s offered %s", tc.key, got)
		p.equal("boot file for "+tc.key, got, url)
	}
	return p.err()
}

// runAutoconfigure covers both halves of RFC 2563 as the plugin implements
// them: a client that sends option 116 is told what to do, and one that does
// not is not answered at all.
func runAutoconfigure(ctx context.Context, w *world) error {
	want, err := w.cfg.Server4.MustArg("autoconfigure", 0)
	if err != nil {
		return err
	}
	offer, err := w.offerFor(ctx, macFor(0x34))
	if err != nil {
		return err
	}
	var p problems
	got, ok := offer.AutoConfigure()
	p.truth("option 116 (autoconfigure)", ok, "the offer carries none, the plugin should have set it")
	if ok {
		p.equal("option 116 (autoconfigure)", got.String(), want)
	}

	// Without the option the plugin ends the chain and sends nothing, which
	// is why every other client in this stack carries one.
	bare, err := dhcpv4.NewDiscovery(macFor(0x35),
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithRequestedOptions(defaultPRL...))
	if err != nil {
		return fmt.Errorf("building the bare DISCOVER: %w", err)
	}
	if err := silence4(ctx, w.v4.onLink, serverBroadcast, bare, isReplyTo(bare)); err != nil {
		return fmt.Errorf("a DISCOVER without option 116: %w", err)
	}
	return p.err()
}

// runIPv6Only asserts both directions: present when asked for, absent
// otherwise, and no address either way because the plugin ends the chain.
func runIPv6Only(ctx context.Context, w *world) error {
	arg, err := w.cfg.Server4.MustArg("ipv6only", 0)
	if err != nil {
		return err
	}
	want, err := time.ParseDuration(arg)
	if err != nil {
		return fmt.Errorf("the configured v6only-wait %q is not a duration: %w", arg, err)
	}

	asked, err := w.offerFor(ctx, macFor(0x36),
		dhcpv4.WithRequestedOptions(append(defaultPRL, dhcpv4.OptionIPv6OnlyPreferred)...))
	if err != nil {
		return err
	}
	var p problems
	got, ok := asked.IPv6OnlyPreferred()
	p.truth("option 108 (IPv6-only preferred)", ok, "the offer carries none for a client that asked for it")
	if ok {
		p.equal("option 108 (IPv6-only preferred)", got.String(), want.String())
	}
	p.truth("the offer to an IPv6-only client", asked.YourIPAddr.IsUnspecified(),
		fmt.Sprintf("carries %s, but the plugin ends the chain so no allocator should have run", asked.YourIPAddr))

	silent, err := w.offerFor(ctx, macFor(0x37))
	if err != nil {
		return err
	}
	_, present := silent.IPv6OnlyPreferred()
	p.truth("option 108 (IPv6-only preferred)", !present, "is in an offer to a client that never asked for it")
	return p.err()
}

func runFile4(ctx context.Context, w *world) error {
	ack, err := w.leaseFor(ctx, w.s.macFile)
	if err != nil {
		return err
	}
	var p problems
	p.equal("the address for the MAC in the lease file", toAddr(ack.YourIPAddr).String(), w.s.fileAddr4.String())
	return p.err()
}

func runNetbox4(ctx context.Context, w *world) error {
	ack, err := w.leaseFor(ctx, w.s.macNetbox)
	if err != nil {
		return err
	}
	var p problems
	p.equal("the address NetBox documents", toAddr(ack.YourIPAddr).String(), w.s.netboxAddr4.String())

	// A MAC the mock answers 404 for is a failed lookup, not an unknown
	// client, and the plugin drops the request rather than letting the pool
	// answer for a machine that is documented somewhere it cannot reach.
	msg, err := discover(w.s.macNetbox404)
	if err != nil {
		return err
	}
	if err := silence4(ctx, w.v4.onLink, serverBroadcast, msg, isReplyTo(msg)); err != nil {
		return fmt.Errorf("a MAC whose NetBox lookup fails: %w", err)
	}
	return p.err()
}

func runRedis4(ctx context.Context, w *world) error {
	ack, err := w.leaseFor(ctx, w.s.macRedis)
	if err != nil {
		return err
	}
	var p problems
	p.equal("the address the Redis hash holds", toAddr(ack.YourIPAddr).String(), w.s.redisAddr4.String())
	// The hash carries its own leaseTime and router, which is how a reply
	// from Redis is told apart from one the option plugins decorated.
	p.equal("the lease time from the Redis hash", ack.IPAddressLeaseTime(0).String(), (90 * time.Minute).String())
	return p.err()
}

func runMacfilter4(ctx context.Context, w *world) error {
	msg, err := discover(w.s.macDenied)
	if err != nil {
		return err
	}
	return silence4(ctx, w.v4.onLink, serverBroadcast, msg, isReplyTo(msg))
}

// runForeignServerID sends a REQUEST addressed to a server that is not this
// one. RFC 2131 has the client name the server it accepted an offer from,
// and a server that is not it must stay quiet.
func runForeignServerID(ctx context.Context, w *world) error {
	mac := macFor(0x38)
	offer, err := w.offerFor(ctx, mac)
	if err != nil {
		return err
	}
	req, err := dhcpv4.NewRequestFromOffer(offer,
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IPv4(192, 0, 2, 200))))
	if err != nil {
		return fmt.Errorf("building the REQUEST: %w", err)
	}
	if serr := silence4(ctx, w.v4.onLink, serverBroadcast, req, isReplyTo(req)); serr != nil {
		return fmt.Errorf("a REQUEST naming 192.0.2.200: %w", serr)
	}

	// The same REQUEST addressed to this server is answered, so the scenario
	// proves the plugin discriminates rather than that the server is deaf.
	ok, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithBroadcast(true))
	if err != nil {
		return fmt.Errorf("building the control REQUEST: %w", err)
	}
	if _, err := exchange4(ctx, w.v4.onLink, serverBroadcast, ok, isReplyTo(ok, dhcpv4.MessageTypeAck), replyBudget); err != nil {
		return fmt.Errorf("the same REQUEST naming this server: %w", err)
	}
	return nil
}

// runReleaseDecline takes two leases, gives one back and refuses the other,
// and records both for the lease API scenario to read.
//
// The release leaves with the leased address as its source. RFC 2131 section
// 4.4.6 has a client unicast a release from the address it is giving up, and
// the relay plugin drops one whose ciaddr does not match the datagram
// source, so a release sent from 0.0.0.0 would be refused before the range
// plugin ever saw it.
func runReleaseDecline(ctx context.Context, w *world) error {
	relMAC := macFor(0x39)
	relAck, err := w.leaseFor(ctx, relMAC)
	if err != nil {
		return fmt.Errorf("taking the lease to release: %w", err)
	}
	relAddr := toAddr(relAck.YourIPAddr)
	// A parameter request list on a RELEASE is unusual, and it is here on
	// purpose: dhcpv4.IsOptionRequested reads an absent list as "everything
	// is requested", so a bare release looks to the ipv6only plugin like a
	// client asking for option 108, and that plugin ends the chain before
	// the allocator can free anything. See README.md, "ipv6only and a
	// release".
	release, err := dhcpv4.NewReleaseFromACK(relAck, dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask))
	if err != nil {
		return fmt.Errorf("building the RELEASE: %w", err)
	}
	if serr := send4(w.v4.onLink.withSource(relAddr), serverBroadcast, release); serr != nil {
		return fmt.Errorf("sending the RELEASE: %w", serr)
	}

	decMAC := macFor(0x3a)
	decAck, err := w.leaseFor(ctx, decMAC)
	if err != nil {
		return fmt.Errorf("taking the lease to decline: %w", err)
	}
	decAddr := toAddr(decAck.YourIPAddr)
	decline, err := dhcpv4.NewRequestFromOffer(decAck,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(decAck.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(decAck.ServerIdentifier())))
	if err != nil {
		return fmt.Errorf("building the DECLINE: %w", err)
	}
	if err := send4(w.v4.onLink, serverBroadcast, decline); err != nil {
		return fmt.Errorf("sending the DECLINE: %w", err)
	}

	w.released = leaseFact{mac: relMAC, addr: relAddr}
	w.declined = leaseFact{mac: decMAC, addr: decAddr}
	w.note("released %s, declined %s", relAddr, decAddr)

	// Neither message is answered, so there is nothing to wait for on the
	// wire. The lease API scenario is what proves they were acted on.
	return nil
}

// runDDNSLeases takes the leases whose DNS records the ddns scenarios read
// back: one with a name of its own, two fighting over one name, and one
// calling itself by a protected name.
func runDDNSLeases(ctx context.Context, w *world) error {
	own := macFor(0x3b)
	ack, err := w.leaseFor(ctx, own, dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
	if err != nil {
		return fmt.Errorf("the client calling itself laptop: %w", err)
	}
	w.ddnsOwn = leaseFact{mac: own, addr: toAddr(ack.YourIPAddr), hostname: "laptop"}

	sharedMAC := macFor(0x3c)
	first, err := w.leaseFor(ctx, sharedMAC, dhcpv4.WithOption(dhcpv4.OptHostName("shared")))
	if err != nil {
		return fmt.Errorf("the first client calling itself shared: %w", err)
	}
	w.ddnsShared = leaseFact{mac: sharedMAC, addr: toAddr(first.YourIPAddr), hostname: "shared"}

	// The second client asks for a name the first already holds. Knot weighs
	// the DHCID prerequisite and refuses, which is the case that matters.
	if _, serr := w.leaseFor(ctx, macFor(0x3d), dhcpv4.WithOption(dhcpv4.OptHostName("shared"))); serr != nil {
		return fmt.Errorf("the second client calling itself shared: %w", serr)
	}

	protMAC := macFor(0x3e)
	prot, err := w.leaseFor(ctx, protMAC, dhcpv4.WithOption(dhcpv4.OptHostName("gateway")))
	if err != nil {
		return fmt.Errorf("the client calling itself gateway: %w", err)
	}
	w.ddnsProtected = leaseFact{mac: protMAC, addr: toAddr(prot.YourIPAddr), hostname: "gateway"}

	w.note("laptop %s, shared %s, gateway claimed by %s",
		w.ddnsOwn.addr, w.ddnsShared.addr, w.ddnsProtected.addr)
	return nil
}

// macFor builds one of the exerciser's client hardware addresses. The prefix
// is locally administered and distinct from the ones the compose file pins
// on the containers, so nothing on the bridge answers for them.
func macFor(last byte) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0x00, 0x00, 0xe0, 0x00, last}
}

// cut is strings.Cut under a shorter name, used where a line is split on its
// first separator only.
func cut(s, sep string) (before, after string, found bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
