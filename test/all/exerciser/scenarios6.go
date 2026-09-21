// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// oroRepeats is how many times the nbp scenario repeats one option code in
// its request list. The plugin is asked for the boot file URL a hundred
// times and has to write option 59 once: an option the server echoes per
// request would otherwise grow the reply by the size of the list.
const oroRepeats = 100

// defaultORO6 is what an ordinary client here asks for.
var defaultORO6 = []dhcpv6.OptionCode{
	dhcpv6.OptionDNSRecursiveNameServer,
	dhcpv6.OptionDomainSearchList,
	dhcpv6.OptionNTPServer,
	dhcpv6.OptionBootfileURL,
}

// solicit builds a SOLICIT with a DUID-LL rather than the DUID-LLT the
// library defaults to. DUID-LL carries the hardware address and a type code
// and nothing else, which is what lets the plugins that key on a MAC address
// recognise a client in a family that has no chaddr field, and it does not
// change between runs the way a timestamped DUID does.
func solicit(mac net.HardwareAddr, mods ...dhcpv6.Modifier) (*dhcpv6.Message, error) {
	base := []dhcpv6.Modifier{
		dhcpv6.WithClientID(duidFor(mac)),
		dhcpv6.WithOption(dhcpv6.OptRequestedOption(defaultORO6...)),
	}
	msg, err := dhcpv6.NewSolicit(mac, append(base, mods...)...)
	if err != nil {
		return nil, fmt.Errorf("building a SOLICIT for %s: %w", mac, err)
	}
	return msg, nil
}

// advertiseFor runs one SOLICIT on the client-side bridge.
func (w *world) advertiseFor(ctx context.Context, mac net.HardwareAddr, mods ...dhcpv6.Modifier) (*dhcpv6.Message, error) {
	msg, err := solicit(mac, mods...)
	if err != nil {
		return nil, err
	}
	got, err := exchange6(ctx, w.v6.client, w.v6.clientMC, msg, isReplyTo6(msg, dhcpv6.MessageTypeAdvertise), replyBudget)
	if err != nil {
		return nil, err
	}
	return got.GetInnerMessage()
}

// leaseFor6 runs a full SOLICIT and REQUEST and returns the Reply.
func (w *world) leaseFor6(ctx context.Context, mac net.HardwareAddr, mods ...dhcpv6.Modifier) (*dhcpv6.Message, error) {
	adv, err := w.advertiseFor(ctx, mac, mods...)
	if err != nil {
		return nil, err
	}
	req, err := dhcpv6.NewRequestFromAdvertise(adv, append([]dhcpv6.Modifier{
		dhcpv6.WithOption(dhcpv6.OptRequestedOption(defaultORO6...)),
	}, mods...)...)
	if err != nil {
		return nil, fmt.Errorf("building a REQUEST from the advertise for %s: %w", mac, err)
	}
	got, err := exchange6(ctx, w.v6.client, w.v6.clientMC, req, isReplyTo6(req, dhcpv6.MessageTypeReply), replyBudget)
	if err != nil {
		return nil, err
	}
	return got.GetInnerMessage()
}

// scenarios6 is the DHCPv6 table.
//
//nolint:funlen // one table entry per plugin, which is the point of the file
func scenarios6() []scenario {
	return []scenario{
		{plugin: "range6", name: "an IA_NA is answered from the configured pool", run: runRange6},
		{plugin: "prefix", name: "an IA_PD is answered with a prefix of the configured size", run: runPrefix6},
		{plugin: "nbp", name: "option 59 appears once for an ORO that repeats its code", run: runNBP6},
		{plugin: "dns", name: "the v6 resolvers match the configuration", run: runDNS6},
		{plugin: "ntp", name: "the NTP server suboption matches the configuration", run: runNTP6},
		{plugin: "searchdomains", name: "the v6 search list matches the configuration", run: runSearch6},
		{plugin: "serverid", name: "the reply carries the configured DUID-LL", run: runServerID6},
		{plugin: "file", name: "a MAC in the static v6 lease file gets exactly that address", run: runFile6},
		{plugin: "macfilter", name: "a DUID-LL on the deny list gets no answer", run: runMacfilter6},
		{plugin: "netbox", name: "a MAC NetBox documents gets its v6 address", run: runNetbox6},
		{plugin: "redis", name: "a MAC with a hash in Redis gets its v6 address", run: runRedis6},
		{plugin: "range6", name: "RELEASE gives the binding back", run: runRelease6},
		{plugin: "relay", name: "a Relay-forward from an unknown source is dropped", run: runRelayRefused6},
		{plugin: "subnet", name: "a relayed request gets the resolvers of the matching scope", run: runSubnet6},
		{plugin: "relayinfo", name: "an interface-id in the mapping file gets its fixed address", run: runRelayInfo6},
		{plugin: "relayinfo", name: "the same interface-id from a source off the allow list is dropped", run: runRelayInfoRefused6},
	}
}

// addressesIn collects every address in every IA_NA of a message.
func addressesIn(msg *dhcpv6.Message) []netip.Addr {
	var out []netip.Addr
	for _, opt := range msg.GetOption(dhcpv6.OptionIANA) {
		iana, ok := opt.(*dhcpv6.OptIANA)
		if !ok {
			continue
		}
		for _, addr := range iana.Options.Addresses() {
			out = append(out, toAddr(addr.IPv6Addr))
		}
	}
	return out
}

func containsAddr(list []netip.Addr, want netip.Addr) bool {
	return slices.Contains(list, want)
}

func renderAddrs(list []netip.Addr) string {
	parts := make([]string, len(list))
	for i, a := range list {
		parts[i] = a.String()
	}
	return strings.Join(parts, " ")
}

// pool6FromConfig reads the range6 pool out of the server's configuration.
func pool6FromConfig(w *world) (addrRange, error) {
	first, err := w.cfg.Server6.MustArg("range6", 1)
	if err != nil {
		return addrRange{}, err
	}
	last, err := w.cfg.Server6.MustArg("range6", 2)
	if err != nil {
		return addrRange{}, err
	}
	f, err1 := netip.ParseAddr(first)
	l, err2 := netip.ParseAddr(last)
	if err := join(err1, err2); err != nil {
		return addrRange{}, fmt.Errorf("the range6 pool does not parse: %w", err)
	}
	return addrRange{first: f, last: l}, nil
}

func runRange6(ctx context.Context, w *world) error {
	mac := macFor(0x50)
	reply, err := w.leaseFor6(ctx, mac, dhcpv6.WithFQDN(0, "laptop6"))
	if err != nil {
		return err
	}
	pool, err := pool6FromConfig(w)
	if err != nil {
		return err
	}
	addrs := addressesIn(reply)
	w.note("the reply carried %d address(es): %s", len(addrs), renderAddrs(addrs))

	var p problems
	p.truth("the reply", len(addrs) == 1, fmt.Sprintf("carries %d IA_NA addresses, expected one", len(addrs)))
	if len(addrs) == 1 {
		p.truth("the leased address", pool.contains(addrs[0]),
			fmt.Sprintf("%s is outside the pool %s range6 is configured with", addrs[0], pool))
		w.v6Lease = leaseFact{mac: mac, addr: addrs[0], hostname: "laptop6"}
		w.ddnsOwn6 = w.v6Lease
	}
	return p.err()
}

func runPrefix6(ctx context.Context, w *world) error {
	poolArg, err := w.cfg.Server6.MustArg("prefix", 0)
	if err != nil {
		return err
	}
	sizeArg, err := w.cfg.Server6.MustArg("prefix", 1)
	if err != nil {
		return err
	}
	pool, err := netip.ParsePrefix(poolArg)
	if err != nil {
		return fmt.Errorf("the prefix plugin's pool %q does not parse: %w", poolArg, err)
	}

	mac := macFor(0x51)
	reply, err := w.leaseFor6(ctx, mac, dhcpv6.WithIAPD([4]byte{0, 0, 0, 1}))
	if err != nil {
		return err
	}

	var got []netip.Prefix
	for _, opt := range reply.GetOption(dhcpv6.OptionIAPD) {
		iapd, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}
		for _, pfx := range iapd.Options.Prefixes() {
			if pfx.Prefix == nil {
				continue
			}
			ones, _ := pfx.Prefix.Mask.Size()
			addr, _ := netip.AddrFromSlice(pfx.Prefix.IP)
			got = append(got, netip.PrefixFrom(addr.Unmap(), ones))
		}
	}
	w.note("the reply delegated %v", got)

	var p problems
	p.truth("the reply", len(got) == 1, fmt.Sprintf("carries %d delegated prefixes, expected one", len(got)))
	if len(got) == 1 {
		p.equal("the delegated prefix length", strconv.Itoa(got[0].Bits()), sizeArg)
		p.truth("the delegated prefix", pool.Contains(got[0].Addr()),
			fmt.Sprintf("%s is outside %s, the pool the prefix plugin carves from", got[0], pool))
		w.v6PD = leaseFact{mac: mac, addr: got[0].Addr()}
	}
	return p.err()
}

// runNBP6 asks for the boot file URL a hundred times over and asserts the
// plugin writes option 59 once.
func runNBP6(ctx context.Context, w *world) error {
	want, err := w.cfg.Server6.MustArg("nbp", 0)
	if err != nil {
		return err
	}
	oro := make([]dhcpv6.OptionCode, 0, oroRepeats)
	for range oroRepeats {
		oro = append(oro, dhcpv6.OptionBootfileURL)
	}
	adv, err := w.advertiseFor(ctx, macFor(0x52), dhcpv6.WithOption(dhcpv6.OptRequestedOption(oro...)))
	if err != nil {
		return err
	}
	opts := adv.GetOption(dhcpv6.OptionBootfileURL)
	w.note("an ORO of %d boot file URL codes produced %d option 59(s)", oroRepeats, len(opts))

	var p problems
	p.truth("option 59 (boot file URL)", len(opts) == 1, fmt.Sprintf("appears %d times, expected once", len(opts)))
	if len(opts) == 1 {
		p.equal("option 59 (boot file URL)", string(opts[0].ToBytes()), want)
	}
	return p.err()
}

func runDNS6(ctx context.Context, w *world) error {
	args, _ := w.cfg.Server6.First("dns")
	adv, err := w.advertiseFor(ctx, macFor(0x53))
	if err != nil {
		return err
	}
	var p problems
	p.equal("the v6 resolvers", ipsToString(adv.Options.DNS()), argsToString(args))
	return p.err()
}

func runNTP6(ctx context.Context, w *world) error {
	args, _ := w.cfg.Server6.First("ntp")
	adv, err := w.advertiseFor(ctx, macFor(0x54))
	if err != nil {
		return err
	}
	var got []net.IP
	for _, opt := range adv.GetOption(dhcpv6.OptionNTPServer) {
		ntp, ok := opt.(*dhcpv6.OptNTPServer)
		if !ok {
			continue
		}
		for _, sub := range ntp.Suboptions {
			if addr, ok := sub.(*dhcpv6.NTPSuboptionSrvAddr); ok {
				got = append(got, net.IP(*addr))
			}
		}
	}
	var p problems
	p.equal("the NTP server suboptions", ipsToString(got), argsToString(args))
	return p.err()
}

func runSearch6(ctx context.Context, w *world) error {
	args, _ := w.cfg.Server6.First("searchdomains")
	adv, err := w.advertiseFor(ctx, macFor(0x55))
	if err != nil {
		return err
	}
	var p problems
	p.equal("the v6 search list", argsToString(adv.Options.DomainSearchList().Labels), argsToString(args))
	return p.err()
}

// runServerID6 checks the DUID the serverid plugin was configured with. A
// client that cannot tell two servers apart cannot honour a Reply either.
func runServerID6(ctx context.Context, w *world) error {
	wantMAC, err := w.cfg.Server6.MustArg("server_id", 1)
	if err != nil {
		return err
	}
	adv, err := w.advertiseFor(ctx, macFor(0x56))
	if err != nil {
		return err
	}
	var p problems
	duid := adv.Options.ServerID()
	if duid == nil {
		p.addf("the advertise carries no server identifier")
		return p.err()
	}
	ll, ok := duid.(*dhcpv6.DUIDLL)
	p.truth("the server identifier", ok, fmt.Sprintf("is a %T, the configuration asks for a DUID-LL", duid))
	if ok {
		p.equal("the server identifier link-layer address", ll.LinkLayerAddr.String(), wantMAC)
	}
	return p.err()
}

func runFile6(ctx context.Context, w *world) error {
	reply, err := w.leaseFor6(ctx, w.s.macFile6)
	if err != nil {
		return err
	}
	addrs := addressesIn(reply)
	var p problems
	p.truth("the address for the MAC in the v6 lease file", containsAddr(addrs, w.s.fileAddr6),
		fmt.Sprintf("the reply carried %s, the file says %s", renderAddrs(addrs), w.s.fileAddr6))
	return p.err()
}

func runMacfilter6(ctx context.Context, w *world) error {
	msg, err := solicit(w.s.macDenied)
	if err != nil {
		return err
	}
	return silence6(ctx, w.v6.client, w.v6.clientMC, msg, isReplyTo6(msg))
}

func runNetbox6(ctx context.Context, w *world) error {
	reply, err := w.leaseFor6(ctx, w.s.macNetbox)
	if err != nil {
		return err
	}
	addrs := addressesIn(reply)
	var p problems
	p.truth("the v6 address NetBox documents", containsAddr(addrs, w.s.netboxAddr6),
		fmt.Sprintf("the reply carried %s, NetBox says %s", renderAddrs(addrs), w.s.netboxAddr6))
	return p.err()
}

func runRedis6(ctx context.Context, w *world) error {
	reply, err := w.leaseFor6(ctx, w.s.macRedis)
	if err != nil {
		return err
	}
	addrs := addressesIn(reply)
	var p problems
	p.truth("the v6 address the Redis hash holds", containsAddr(addrs, w.s.redisAddr6),
		fmt.Sprintf("the reply carried %s, the hash says %s", renderAddrs(addrs), w.s.redisAddr6))
	return p.err()
}

// runRelease6 takes a binding, gives it back, and then asks again: the pool
// has to be willing to hand the same address out.
func runRelease6(ctx context.Context, w *world) error {
	mac := macFor(0x57)
	reply, err := w.leaseFor6(ctx, mac)
	if err != nil {
		return fmt.Errorf("taking the binding to release: %w", err)
	}
	addrs := addressesIn(reply)
	if len(addrs) != 1 {
		return fmt.Errorf("the reply carried %d addresses, expected one", len(addrs))
	}

	release, err := dhcpv6.NewMessage()
	if err != nil {
		return fmt.Errorf("building the RELEASE: %w", err)
	}
	release.MessageType = dhcpv6.MessageTypeRelease
	release.AddOption(dhcpv6.OptClientID(duidFor(mac)))
	if sid := reply.Options.ServerID(); sid != nil {
		release.AddOption(dhcpv6.OptServerID(sid))
	}
	release.AddOption(dhcpv6.OptElapsedTime(0))
	if iana := reply.Options.OneIANA(); iana != nil {
		release.AddOption(iana)
	}
	if _, err := exchange6(ctx, w.v6.client, w.v6.clientMC, release, isReplyTo6(release, dhcpv6.MessageTypeReply), replyBudget); err != nil {
		return fmt.Errorf("sending the RELEASE: %w", err)
	}

	w.note("released %s", addrs[0])
	w.v6Lease = leaseFact{mac: mac, addr: addrs[0]}
	return nil
}

// runRelayRefused6 forwards from this container's link-local address on the
// relay bridge. The relay plugin matches the datagram source on DHCPv6, and
// the allow list names the global address, so a link-local source is exactly
// the "from somewhere else" case.
func runRelayRefused6(ctx context.Context, w *world) error {
	inner, err := solicit(macFor(0x58))
	if err != nil {
		return err
	}
	rm, err := wrapRelay6(inner, w.s.selfRLY6, w.s.selfLAN6, "")
	if err != nil {
		return err
	}
	ll, err := linkLocalOn(w.s.selfRLY6)
	if err != nil {
		return err
	}
	// Binding a source explicitly is what makes this a different peer than
	// the socket the other relay scenarios use.
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ll.AsSlice(), Port: 0, Zone: zoneOf(w.s.selfRLY6)})
	if err != nil {
		return fmt.Errorf("binding a link-local source: %w", err)
	}
	defer func() { _ = conn.Close() }()

	dst := &net.UDPAddr{IP: w.s.serverRLY6.AsSlice(), Port: dhcpv6.DefaultServerPort}
	return silence6(ctx, conn, dst, rm, isReplyTo6(inner))
}

func runSubnet6(ctx context.Context, w *world) error {
	inner, err := solicit(macFor(0x59))
	if err != nil {
		return err
	}
	rm, err := wrapRelay6(inner, w.s.selfRLY6, w.s.selfLAN6, "")
	if err != nil {
		return err
	}
	got, err := exchange6(ctx, w.v6.relay, w.v6.serverRLY, rm, isReplyTo6(inner, dhcpv6.MessageTypeAdvertise), replyBudget)
	if err != nil {
		return err
	}
	adv, err := got.GetInnerMessage()
	if err != nil {
		return fmt.Errorf("reading the relayed advertise: %w", err)
	}
	var p problems
	p.equal("the resolvers of the relayed scope", ipsToString(adv.Options.DNS()), w.s.subnetDNS6.String())

	// The top-level dns plugin is configured with different resolvers, so
	// this also proves the scope overwrote them.
	onLink, _ := w.cfg.Server6.First("dns")
	p.truth("the scope's resolvers", ipsToString(adv.Options.DNS()) != argsToString(onLink),
		"match the dns plugin's, so the reply does not show which of the two answered")
	return p.err()
}

func runRelayInfo6(ctx context.Context, w *world) error {
	inner, err := solicit(macFor(0x5a))
	if err != nil {
		return err
	}
	rm, err := wrapRelay6(inner, w.s.selfRLY6, w.s.selfLAN6, w.s.interfaceID)
	if err != nil {
		return err
	}
	got, err := exchange6(ctx, w.v6.relay, w.v6.serverRLY, rm, isReplyTo6(inner, dhcpv6.MessageTypeAdvertise), replyBudget)
	if err != nil {
		return err
	}
	adv, err := got.GetInnerMessage()
	if err != nil {
		return fmt.Errorf("reading the relayed advertise: %w", err)
	}
	addrs := addressesIn(adv)
	w.note("the relayed advertise carried %s", renderAddrs(addrs))

	var p problems
	// Containment rather than equality: relayinfo adds its IA_NA and lets
	// the chain continue, so range6 adds one of its own behind it and the
	// reply carries both. See README.md, "two IA_NA options".
	p.truth("the address mapped to interface-id "+w.s.interfaceID, containsAddr(addrs, w.s.relayinfoAddr6),
		fmt.Sprintf("the reply carried %s, the mapping file says %s", renderAddrs(addrs), w.s.relayinfoAddr6))
	return p.err()
}

// runRelayInfoRefused6 sends the same stamped Relay-forward to the server's
// address on the client-side bridge, so the datagram source is this
// container's address there. The relay plugin's allow list names it, the
// relayinfo plugin's does not.
func runRelayInfoRefused6(ctx context.Context, w *world) error {
	inner, err := solicit(macFor(0x5b))
	if err != nil {
		return err
	}
	rm, err := wrapRelay6(inner, w.s.selfRLY6, w.s.selfLAN6, w.s.interfaceID)
	if err != nil {
		return err
	}
	return silence6(ctx, w.v6.relay, w.v6.serverLAN, rm, isReplyTo6(inner))
}

// linkLocalOn returns the link-local address of the interface that carries
// global.
func linkLocalOn(global netip.Addr) (netip.Addr, error) {
	iface, err := interfaceFor(global)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := dhcpv6.GetLinkLocalAddr(iface.Name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no link-local address on %s: %w", iface.Name, err)
	}
	return toAddr(ip), nil
}

// zoneOf returns the interface name a link-local socket on the same link as
// global has to be scoped to.
func zoneOf(global netip.Addr) string {
	iface, err := interfaceFor(global)
	if err != nil {
		return ""
	}
	return iface.Name
}
