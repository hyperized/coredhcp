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

// maxHostname caps the name copied into an event. The name comes from the
// client and is only ever displayed, so this is about not carrying an
// oversized string around rather than about validating it: the observer still
// has to sanitise whatever it renders. A DHCPv4 option cannot exceed this
// anyway; a DHCPv6 FQDN can.
const maxHostname = 255

// requestReport builds the events.Request for one packet as the handler walks
// it, and hands the finished event to the observer on the way out.
//
// A nil *requestReport is the case where nobody is watching. Every method
// returns at once on a nil receiver, so an unobserved server pays one nil
// check per exit point and allocates nothing.
type requestReport struct {
	obs     events.Observer
	ev      events.Request
	chainAt time.Time
}

// newReport starts the event for one packet. Callers have already established
// that an observer is attached. Time is taken here, which is as close to the
// read from the socket as the handler gets.
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

// chainStart marks the point the plugin chain is entered. Duration covers the
// chain and nothing else, so parsing and sending stay out of it.
func (r *requestReport) chainStart() {
	if r == nil {
		return
	}
	r.chainAt = time.Now()
}

// chainDone4 records what the DHCPv4 chain cost and which plugin, if any,
// stopped it. at is the index applyHandlers4 stopped on, or -1 when every
// plugin ran. Position is 1-based because it is shown to people.
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

// chainDone6 is chainDone4 for the DHCPv6 chain.
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

// emit hands the finished event to the observer. Every exit path through the
// handlers ends in exactly one of these, so an observer sees one event per
// datagram.
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

// emit4 is emit for a DHCPv4 datagram, reading off the destination whether the
// reply was broadcast or unicast. Raw frames do not come through here: they
// report events.PathLayer2 themselves.
func (r *requestReport) emit4(outcome events.Outcome, peer *net.UDPAddr, err error) {
	if r == nil {
		return
	}
	r.emit(outcome, replyPath4(peer), err)
}

// request4 fills in what the DHCPv4 request says about the client.
func (r *requestReport) request4(req *dhcpv4.DHCPv4) {
	if r == nil {
		return
	}
	r.ev.Type = req.MessageType().String()
	r.ev.ClientID = req.ClientHWAddr.String()
	r.ev.Hostname = capHostname(req.HostName())
	r.ev.Relay = addrFrom(req.GatewayIPAddr)
}

// reply4 fills in what the DHCPv4 reply hands out.
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

// request6 fills in what the DHCPv6 request says about the client. It reads
// the inner message, so a relayed request describes the client rather than
// the relay. A request whose inner message does not parse still produces an
// event, with the fields the server could read left empty.
func (r *requestReport) request6(req dhcpv6.DHCPv6) {
	if r == nil {
		return
	}
	// The outermost wrapper is the relay closest to the server, which is the
	// one whose link address says where the request entered the network.
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

// reply6 fills in what the DHCPv6 reply hands out. resp may already be
// wrapped in a relay-reply by the time it gets here, so it is unwrapped: what
// the client receives sits in the inner message either way.
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

// addAddresses6 adds every address of one identity association as a /128.
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

// addPrefixes6 adds every delegated prefix of one identity association, at the
// length it was delegated with.
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

// fqdn6 is the name the client sent in its FQDN option, empty when it sent
// none. rfc1035label renders its labels as a Go slice literal, so they are
// joined here instead.
func fqdn6(msg *dhcpv6.Message) string {
	opt := msg.Options.FQDN()
	if opt == nil || opt.DomainName == nil {
		return ""
	}
	return strings.Join(opt.DomainName.Labels, ".")
}

// shorterLease keeps the shortest non-zero of two lifetimes. A DHCPv6 reply
// can hand out several addresses with different lifetimes while the event
// holds one number, so it holds the one that expires first.
func shorterLease(cur, next time.Duration) time.Duration {
	if cur == 0 || (next > 0 && next < cur) {
		return next
	}
	return cur
}

// addrFrom converts a net.IP to a netip.Addr, unmapping 4-in-6 so a DHCPv4
// address never reads as ::ffff:a.b.c.d. An unset, malformed or all-zero
// address becomes the zero Addr, which the event contract reads as "not set".
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

// peerAddrPort is the datagram's source address. A DHCPv4 peer arrives as a
// 4-in-6 address on a dual-stack socket, so it is unmapped here to read as
// 192.0.2.1:68 rather than [::ffff:192.0.2.1]:68.
func peerAddrPort(peer *net.UDPAddr) netip.AddrPort {
	if peer == nil {
		return netip.AddrPort{}
	}
	ap := peer.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// capHostname trims a client-supplied name to maxHostname bytes. The bytes
// are left as they arrived: sanitising them is the display's job, and the
// event should say what the client actually sent.
func capHostname(name string) string {
	if len(name) > maxHostname {
		return name[:maxHostname]
	}
	return name
}

// replyPath4 says how a DHCPv4 datagram left: broadcast when it went to
// 255.255.255.255, unicast to the client, its current address or a relay
// otherwise.
func replyPath4(peer *net.UDPAddr) events.ReplyPath {
	if peer != nil && peer.IP.Equal(net.IPv4bcast) {
		return events.PathBroadcast
	}
	return events.PathUnicast
}
