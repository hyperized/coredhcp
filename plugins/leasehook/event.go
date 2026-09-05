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
	familyV4 = 4
	familyV6 = 6

	// Host routes, not subnets: see the payload section of the package doc.
	hostPrefixV4 = "/32"
	hostPrefixV6 = "/128"

	// RFC 1035 section 2.3.4: 255 bytes is the longest a domain name may be,
	// so nothing legitimate is lost by capping the attacker-controlled hostname here.
	maxHostnameBytes = 255
)

var allEvents = []string{eventOffer, eventAck, eventNak, eventReply, eventRelease, eventDecline}

// The default allow-list. Read only: applyEvents builds a fresh map rather
// than narrowing this one.
var knownEvents = eventSet(allEvents)

func eventSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

func eventNames() string {
	return strings.Join(allEvents, ", ")
}

// Field order here is the JSON key order, kept stable so output compares
// byte for byte.
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

var leaseEvent4 = map[dhcpv4.MessageType]string{
	dhcpv4.MessageTypeOffer: eventOffer,
	dhcpv4.MessageTypeAck:   eventAck,
}

// ok is false when the exchange is not something this plugin reports.
func event4(req, resp *dhcpv4.DHCPv4, now time.Time) (event, bool) {
	// RELEASE and DECLINE dispatch on the request: the server answers
	// neither, so the response carries no message type or address at all.
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

func answer4(req, resp *dhcpv4.DHCPv4, now time.Time) (event, bool) {
	mt := resp.MessageType()
	if mt == dhcpv4.MessageTypeNak {
		return base4(eventNak, req, now), true
	}
	name, ok := leaseEvent4[mt]
	if !ok || !hasAddr(resp.YourIPAddr) {
		// Only worth reporting once an allocator has filled yiaddr, which
		// is why this plugin runs last in the chain.
		return event{}, false
	}
	ev := withAddress4(base4(name, req, now), resp.YourIPAddr)
	ev.LeaseSeconds = int64(resp.IPAddressLeaseTime(0) / time.Second)
	return ev, true
}

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

func withAddress4(ev event, ip net.IP) event {
	if !hasAddr(ip) {
		return ev
	}
	ev.Addresses = []string{ip.String() + hostPrefixV4}
	return ev
}

// An unset DHCPv4 header field shows up as either empty or all zeroes, hence both checks.
func hasAddr(ip net.IP) bool {
	return len(ip) > 0 && !ip.IsUnspecified()
}

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

// Addresses and prefixes come from the client's own message, not the reply:
// the client names what it is handing back or refusing.
func released6(name string, req dhcpv6.DHCPv6, msg *dhcpv6.Message, now time.Time) event {
	ev := base6(name, req, msg, now)
	ev.Addresses, _ = addresses6(msg)
	ev.Prefixes, _ = delegations6(msg)
	return ev
}

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

// lease_seconds reports the first address's lifetime, or the first prefix's
// when the reply delegates without addressing.
func firstValid(addrValid, pdValid time.Duration) time.Duration {
	if addrValid != 0 {
		return addrValid
	}
	return pdValid
}

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
	// The MAC is only present when the DUID or a relay option happens to
	// carry one, so its absence is normal and not worth a log line.
	if mac, err := dhcpv6.ExtractMAC(req); err == nil {
		ev.MAC = mac.String()
	}
	if link := relayLinkAddr(req); hasAddr(link) {
		ev.Relay = link.String()
	}
	return ev
}

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

func fqdn6(msg *dhcpv6.Message) string {
	opt := msg.Options.FQDN()
	if opt == nil || opt.DomainName == nil {
		return ""
	}
	return strings.Join(opt.DomainName.Labels, ".")
}

// The innermost relay sits on the client's own link, the address an IPAM
// wants; the outermost only names where the next relay sits.
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

// Backs off to a rune boundary so the cut cannot leave a partial rune
// behind. limit is always well above utf8.UTFMax here, so this cannot empty s.
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
