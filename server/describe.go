// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/plugins"
)

// A cap, not validation: the observer still has to sanitise what it renders.
// A DHCPv4 option cannot exceed this anyway; a DHCPv6 FQDN can.
const maxHostname = 255

// requestReport builds the events.Request for one packet as the handler walks it.
// A nil receiver means nobody is watching, and every method returns at once.
type requestReport struct {
	obs     events.Observer
	ev      events.Request
	chainAt time.Time
}

// The clock is read here, as close to the socket read as the handler gets.
func newReport(obs events.Observer, family events.Family, iface string, peer *net.UDPAddr) *requestReport {
	return &requestReport{
		obs: obs,
		ev: events.Request{
			Time:      time.Now(),
			Family:    family,
			Interface: iface,
			Peer:      peerAddrPort(peer),
		},
	}
}

// Duration covers the chain and nothing else: parsing and sending stay out.
func (r *requestReport) chainStart() {
	if r == nil {
		return
	}
	r.chainAt = time.Now()
}

// at is applyHandlers4's stop index, -1 when every plugin ran. Position is
// 1-based because it is shown to people.
func (r *requestReport) chainDone4(chain []plugins.Link4, at int) {
	if r == nil {
		return
	}
	r.ev.Duration = time.Since(r.chainAt)
	if at >= 0 {
		r.ev.Plugin = chain[at].Name
		r.ev.Position = at + 1
	}
}

func (r *requestReport) chainDone6(chain []plugins.Link6, at int) {
	if r == nil {
		return
	}
	r.ev.Duration = time.Since(r.chainAt)
	if at >= 0 {
		r.ev.Plugin = chain[at].Name
		r.ev.Position = at + 1
	}
}

// Every exit path through the handlers ends in exactly one of these, so an
// observer sees one event per datagram.
func (r *requestReport) emit(outcome events.Outcome, path events.ReplyPath, err error) {
	if r == nil {
		return
	}
	r.ev.Outcome = outcome
	r.ev.Path = path
	if err != nil {
		r.ev.Error = err.Error()
	}
	r.obs.Request(r.ev)
}

// Raw frames do not come through here: they report events.PathLayer2 themselves.
func (r *requestReport) emit4(outcome events.Outcome, peer *net.UDPAddr, err error) {
	if r == nil {
		return
	}
	r.emit(outcome, replyPath4(peer), err)
}

func (r *requestReport) request4(req *dhcpv4.DHCPv4) {
	if r == nil {
		return
	}
	r.ev.Type = req.MessageType().String()
	r.ev.ClientID = req.ClientHWAddr.String()
	r.ev.Hostname = capHostname(req.HostName())
	r.ev.Relay = addrFrom(req.GatewayIPAddr)
}

func (r *requestReport) reply4(resp *dhcpv4.DHCPv4) {
	if r == nil {
		return
	}
	r.ev.ReplyType = resp.MessageType().String()
	r.ev.LeaseTime = resp.IPAddressLeaseTime(0)
	if addr := addrFrom(resp.YourIPAddr); addr.IsValid() {
		r.ev.Addresses = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}
	}
}

// Reads the inner message, so a relayed request describes the client rather
// than the relay. An inner message that will not parse still produces an event.
func (r *requestReport) request6(req dhcpv6.DHCPv6) {
	if r == nil {
		return
	}
	// The outermost wrapper is the relay nearest the server, whose link
	// address says where the request entered the network.
	if relay, ok := req.(*dhcpv6.RelayMessage); ok {
		r.ev.Relay = addrFrom(relay.LinkAddr)
	}
	msg, err := req.GetInnerMessage()
	if err != nil {
		return
	}
	r.ev.Type = msg.Type().String()
	if duid := msg.Options.ClientID(); duid != nil {
		r.ev.ClientID = hex.EncodeToString(duid.ToBytes())
	}
	r.ev.Hostname = capHostname(fqdn6(msg))
}

// resp may already be wrapped in a relay-reply here; what the client receives
// sits in the inner message either way.
func (r *requestReport) reply6(resp dhcpv6.DHCPv6) {
	if r == nil {
		return
	}
	msg, err := resp.GetInnerMessage()
	if err != nil {
		return
	}
	r.ev.ReplyType = msg.Type().String()
	for _, ia := range msg.Options.IANA() {
		r.addAddresses6(ia.Options.Addresses())
	}
	for _, ia := range msg.Options.IATA() {
		r.addAddresses6(ia.Options.Addresses())
	}
	for _, pd := range msg.Options.IAPD() {
		r.addPrefixes6(pd.Options.Prefixes())
	}
}

func (r *requestReport) addAddresses6(addrs []*dhcpv6.OptIAAddress) {
	for _, a := range addrs {
		addr := addrFrom(a.IPv6Addr)
		if !addr.IsValid() {
			continue
		}
		r.ev.Addresses = append(r.ev.Addresses, netip.PrefixFrom(addr, addr.BitLen()))
		r.ev.LeaseTime = shorterLease(r.ev.LeaseTime, a.ValidLifetime)
	}
}

// Prefixes keep the length they were delegated with, unlike addresses.
func (r *requestReport) addPrefixes6(prefixes []*dhcpv6.OptIAPrefix) {
	for _, p := range prefixes {
		if p.Prefix == nil {
			continue
		}
		addr := addrFrom(p.Prefix.IP)
		if !addr.IsValid() {
			continue
		}
		ones, _ := p.Prefix.Mask.Size()
		r.ev.Addresses = append(r.ev.Addresses, netip.PrefixFrom(addr, ones))
		r.ev.LeaseTime = shorterLease(r.ev.LeaseTime, p.ValidLifetime)
	}
}

// rfc1035label renders its labels as a Go slice literal, so they are joined here.
func fqdn6(msg *dhcpv6.Message) string {
	opt := msg.Options.FQDN()
	if opt == nil || opt.DomainName == nil {
		return ""
	}
	return strings.Join(opt.DomainName.Labels, ".")
}

// A DHCPv6 reply can carry several lifetimes while the event holds one, so it
// holds the one that expires first.
func shorterLease(cur, next time.Duration) time.Duration {
	if cur == 0 || (next > 0 && next < cur) {
		return next
	}
	return cur
}

// Unmaps 4-in-6 so a DHCPv4 address never reads as ::ffff:a.b.c.d. Anything
// unset or malformed becomes the zero Addr, which the event reads as "not set".
func addrFrom(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}
	}
	return addr
}

// A DHCPv4 peer arrives 4-in-6 on a dual-stack socket, so it is unmapped to
// read as 192.0.2.1:68 rather than [::ffff:192.0.2.1]:68.
func peerAddrPort(peer *net.UDPAddr) netip.AddrPort {
	if peer == nil {
		return netip.AddrPort{}
	}
	ap := peer.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// The bytes are left as they arrived: the event should say what the client
// sent, and sanitising is the display's job.
func capHostname(name string) string {
	if len(name) > maxHostname {
		return name[:maxHostname]
	}
	return name
}

// Anything not sent to 255.255.255.255 counts as unicast, relays included.
func replyPath4(peer *net.UDPAddr) events.ReplyPath {
	if peer != nil && peer.IP.Equal(net.IPv4bcast) {
		return events.PathBroadcast
	}
	return events.PathUnicast
}
