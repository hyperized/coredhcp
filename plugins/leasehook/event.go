// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasehook

import (
	"encoding/hex"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// The event names, which are also what events: accepts.
const (
	eventOffer   = "offer"
	eventAck     = "ack"
	eventNak     = "nak"
	eventReply   = "reply"
	eventRelease = "release"
	eventDecline = "decline"
)

const (
	// familyV4 and familyV6 are the "family" field.
	familyV4 = 4
	familyV6 = 6

	// hostPrefixV4 and hostPrefixV6 turn a leased address into the host route
	// the addresses field reports. See the payload section of the package
	// documentation for why a lease is never reported as a subnet.
	hostPrefixV4 = "/32"
	hostPrefixV6 = "/128"

	// maxHostnameBytes caps the hostname copied out of a packet. Option 12
	// and the DHCPv6 FQDN option are both attacker-controlled and as long as
	// their encoding allows; 255 bytes is the longest a domain name may be
	// (RFC 1035 section 2.3.4), so nothing legitimate is lost.
	maxHostnameBytes = 255
)

// allEvents lists every event name in the order they are documented. It is
// read only.
var allEvents = []string{eventOffer, eventAck, eventNak, eventReply, eventRelease, eventDecline}

// knownEvents is allEvents as a set, and doubles as the default allow-list.
// It is read only: applyEvents builds a fresh map rather than narrowing this
// one.
var knownEvents = eventSet(allEvents)

// eventSet turns a list of event names into a set.
func eventSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// eventNames lists the event names for an error message.
func eventNames() string {
	return strings.Join(allEvents, ", ")
}

// event is one lease event, and is exactly what gets serialised as the JSON
// body. The field order here is the key order in that body, which is what
// makes the output stable enough to compare byte for byte.
type event struct {
	Family        int      `json:"family"`
	Event         string   `json:"event"`
	Time          string   `json:"time"`
	MAC           string   `json:"mac,omitempty"`
	DUID          string   `json:"duid,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	Prefixes      []string `json:"prefixes,omitempty"`
	LeaseSeconds  int64    `json:"lease_seconds,omitempty"`
	Relay         string   `json:"relay,omitempty"`
	TransactionID string   `json:"transaction_id,omitempty"`
}

// leaseEvent4 maps the two response types that carry an address to their
// event name. It is read only.
var leaseEvent4 = map[dhcpv4.MessageType]string{
	dhcpv4.MessageTypeOffer: eventOffer,
	dhcpv4.MessageTypeAck:   eventAck,
}

// event4 builds the event for one DHCPv4 exchange. ok is false when the
// exchange is not something this plugin reports.
func event4(req, resp *dhcpv4.DHCPv4, now time.Time) (event, bool) {
	// RELEASE and DECLINE are dispatched on the request: the server answers
	// neither, so the response the chain carries has no message type at all
	// and says nothing about which address the client means.
	switch req.MessageType() {
	case dhcpv4.MessageTypeRelease:
		return withAddress4(base4(eventRelease, req, now), req.ClientIPAddr), true
	case dhcpv4.MessageTypeDecline:
		return withAddress4(base4(eventDecline, req, now), req.RequestedIPAddress()), true
	}
	if resp == nil {
		return event{}, false
	}
	return answer4(req, resp, now)
}

// answer4 builds the event for the answer the chain produced, when that
// answer is one of the three worth reporting.
func answer4(req, resp *dhcpv4.DHCPv4, now time.Time) (event, bool) {
	mt := resp.MessageType()
	if mt == dhcpv4.MessageTypeNak {
		return base4(eventNak, req, now), true
	}
	name, ok := leaseEvent4[mt]
	if !ok || !hasAddr(resp.YourIPAddr) {
		// An OFFER or an ACK is only worth reporting once an allocator has
		// put an address in yiaddr, which is the reason this plugin belongs
		// last in the chain.
		return event{}, false
	}
	ev := withAddress4(base4(name, req, now), resp.YourIPAddr)
	ev.LeaseSeconds = int64(resp.IPAddressLeaseTime(0) / time.Second)
	return ev, true
}

// base4 fills the fields every DHCPv4 event carries.
func base4(name string, req *dhcpv4.DHCPv4, now time.Time) event {
	ev := event{
		Family:        familyV4,
		Event:         name,
		Time:          now.UTC().Format(time.RFC3339),
		MAC:           req.ClientHWAddr.String(),
		Hostname:      truncateUTF8(req.HostName(), maxHostnameBytes),
		TransactionID: hex.EncodeToString(req.TransactionID[:]),
	}
	if hasAddr(req.GatewayIPAddr) {
		ev.Relay = req.GatewayIPAddr.String()
	}
	return ev
}

// withAddress4 reports one leased IPv4 address, when there is one.
func withAddress4(ev event, ip net.IP) event {
	if !hasAddr(ip) {
		return ev
	}
	ev.Addresses = []string{ip.String() + hostPrefixV4}
	return ev
}

// hasAddr reports whether ip names an address rather than "none". A DHCPv4
// header field that was never filled in is either empty or all zeroes.
func hasAddr(ip net.IP) bool {
	return len(ip) > 0 && !ip.IsUnspecified()
}

// event6 builds the event for one DHCPv6 exchange.
func event6(req, resp dhcpv6.DHCPv6, now time.Time) (event, bool) {
	reqMsg, err := req.GetInnerMessage()
	if err != nil {
		log.Debugf("could not decapsulate the request, reporting nothing: %v", err)
		return event{}, false
	}
	switch reqMsg.Type() {
	case dhcpv6.MessageTypeRelease:
		return released6(eventRelease, req, reqMsg, now), true
	case dhcpv6.MessageTypeDecline:
		return released6(eventDecline, req, reqMsg, now), true
	}
	return replied6(req, reqMsg, resp, now)
}

// released6 reports what the client says it is handing back or refusing,
// which its own message names rather than the reply.
func released6(name string, req dhcpv6.DHCPv6, msg *dhcpv6.Message, now time.Time) event {
	ev := base6(name, req, msg, now)
	ev.Addresses, _ = addresses6(msg)
	ev.Prefixes, _ = delegations6(msg)
	return ev
}

// replied6 reports a Reply that hands out at least one address or prefix.
func replied6(req dhcpv6.DHCPv6, reqMsg *dhcpv6.Message, resp dhcpv6.DHCPv6, now time.Time) (event, bool) {
	if resp == nil {
		return event{}, false
	}
	respMsg, err := resp.GetInnerMessage()
	if err != nil {
		log.Debugf("could not decapsulate the response, reporting nothing: %v", err)
		return event{}, false
	}
	if respMsg.Type() != dhcpv6.MessageTypeReply {
		return event{}, false
	}
	addrs, valid := addresses6(respMsg)
	prefixes, pdValid := delegations6(respMsg)
	if len(addrs) == 0 && len(prefixes) == 0 {
		return event{}, false
	}
	ev := base6(eventReply, req, reqMsg, now)
	ev.Addresses, ev.Prefixes = addrs, prefixes
	ev.LeaseSeconds = int64(firstValid(valid, pdValid) / time.Second)
	return ev, true
}

// firstValid picks the lifetime that lease_seconds reports: the one belonging
// to the first address, or to the first prefix when the reply delegates
// without addressing.
func firstValid(addrValid, pdValid time.Duration) time.Duration {
	if addrValid != 0 {
		return addrValid
	}
	return pdValid
}

// base6 fills the fields every DHCPv6 event carries.
func base6(name string, req dhcpv6.DHCPv6, msg *dhcpv6.Message, now time.Time) event {
	ev := event{
		Family:        familyV6,
		Event:         name,
		Time:          now.UTC().Format(time.RFC3339),
		Hostname:      truncateUTF8(fqdn6(msg), maxHostnameBytes),
		TransactionID: hex.EncodeToString(msg.TransactionID[:]),
	}
	if duid := msg.Options.ClientID(); duid != nil {
		ev.DUID = hex.EncodeToString(duid.ToBytes())
	}
	// A DHCPv6 client is identified by its DUID; the MAC is only there when
	// the DUID or a relay option happens to carry one, so its absence is
	// normal and not worth a log line.
	if mac, err := dhcpv6.ExtractMAC(req); err == nil {
		ev.MAC = mac.String()
	}
	if link := relayLinkAddr(req); hasAddr(link) {
		ev.Relay = link.String()
	}
	return ev
}

// addresses6 reads the IA_NA addresses out of a message, with the valid
// lifetime of the first one.
func addresses6(msg *dhcpv6.Message) ([]string, time.Duration) {
	var out []string
	var valid time.Duration
	for _, iana := range msg.Options.IANA() {
		for _, addr := range iana.Options.Addresses() {
			if len(addr.IPv6Addr) == 0 {
				continue
			}
			if len(out) == 0 {
				valid = addr.ValidLifetime
			}
			out = append(out, addr.IPv6Addr.String()+hostPrefixV6)
		}
	}
	return out, valid
}

// delegations6 reads the IA_PD prefixes out of a message, with the valid
// lifetime of the first one.
func delegations6(msg *dhcpv6.Message) ([]string, time.Duration) {
	var out []string
	var valid time.Duration
	for _, iapd := range msg.Options.IAPD() {
		for _, prefix := range iapd.Options.Prefixes() {
			if prefix.Prefix == nil {
				continue
			}
			if len(out) == 0 {
				valid = prefix.ValidLifetime
			}
			out = append(out, prefix.Prefix.String())
		}
	}
	return out, valid
}

// fqdn6 returns the name the client asked for in its FQDN option, empty when
// it sent none.
func fqdn6(msg *dhcpv6.Message) string {
	opt := msg.Options.FQDN()
	if opt == nil || opt.DomainName == nil {
		return ""
	}
	return strings.Join(opt.DomainName.Labels, ".")
}

// relayLinkAddr returns the link address of the relay closest to the client,
// or nil when the request did not come through one.
//
// The innermost relay is the one on the client's own link, which is the
// address an IPAM wants. The outermost, which is what the server holds, only
// names the link the next relay sits on.
func relayLinkAddr(pkt dhcpv6.DHCPv6) net.IP {
	var link net.IP
	for {
		relay, ok := pkt.(*dhcpv6.RelayMessage)
		if !ok {
			return link
		}
		link = relay.LinkAddr
		inner, err := dhcpv6.DecapsulateRelay(relay)
		if err != nil {
			return link
		}
		pkt = inner
	}
}

// truncateUTF8 caps s at max bytes, backing off to a rune boundary so the cut
// itself cannot leave a partial rune behind. Invalid bytes that were already
// in s are left alone; encoding/json escapes them on the way out.
//
// limit is always well above utf8.UTFMax here, so the loop cannot empty s.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for range utf8.UTFMax - 1 {
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
