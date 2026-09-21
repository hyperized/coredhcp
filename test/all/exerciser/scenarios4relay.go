// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// circuitIDSubOption is sub-option 1 of the relay agent information option,
// RFC 3046 section 3.1.
const circuitIDSubOption = dhcpv4.GenericOptionCode(1)

// relayedDiscover builds the DISCOVER a relay agent would forward: giaddr
// set, no broadcast flag, because the server answers giaddr at the source
// port of the request rather than the client's link.
func relayedDiscover(mac net.HardwareAddr, giaddr netip.Addr, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
	base := []dhcpv4.Modifier{
		dhcpv4.WithGatewayIP(giaddr.AsSlice()),
		dhcpv4.WithRequestedOptions(defaultPRL...),
		dhcpv4.WithOption(dhcpv4.OptAutoConfigure(dhcpv4.AutoConfigure)),
	}
	msg, err := dhcpv4.NewDiscovery(mac, append(base, mods...)...)
	if err != nil {
		return nil, fmt.Errorf("building a relayed DISCOVER for %s: %w", mac, err)
	}
	return msg, nil
}

// withCircuitID stamps the option 82 a relay writes when it forwards a
// request from a subscriber port.
func withCircuitID(id string) dhcpv4.Modifier {
	return dhcpv4.WithOption(dhcpv4.OptRelayAgentInfo(dhcpv4.OptGeneric(circuitIDSubOption, []byte(id))))
}

// scenarios4Relay is the relayed DHCPv4 table.
//
// The exerciser plays the relay from its address on the second bridge. Two
// plugins gate these requests and they gate on different things, which is
// what lets one socket cover both allow lists: the relay plugin matches
// giaddr, and the relayinfo plugin matches the source address of the
// datagram. Their package documentation says so in as many words.
func scenarios4Relay() []scenario {
	return []scenario{
		{
			plugin: "relay",
			name:   "a relayed DISCOVER naming an unknown giaddr is dropped",
			run:    runRelayRefused4,
		},
		{
			plugin: "subnet",
			name:   "a relayed DISCOVER is served from the scope mapped to its relay",
			run:    runSubnet4,
		},
		{
			plugin: "relayinfo",
			name:   "a circuit-id in the mapping file gets its fixed address",
			run:    runRelayInfo4,
		},
		{
			plugin: "relayinfo",
			name:   "the same circuit-id from a source off the allow list is dropped",
			run:    runRelayInfoRefused4,
		},
	}
}

// runRelayRefused4 forwards from the allowed relay but claims a giaddr on
// neither bridge. Answering it would make the server reflect an OFFER at any
// routable address, which is the reflection the allow list exists to refuse.
func runRelayRefused4(ctx context.Context, w *world) error {
	msg, err := relayedDiscover(macFor(0x40), w.s.foreignRLY4)
	if err != nil {
		return err
	}
	dst := &net.UDPAddr{IP: w.s.serverRLY4.AsSlice(), Port: dhcpv4.ServerPort}
	return silence4(ctx, w.v4.relay, dst, msg, isReplyTo(msg))
}

// runSubnet4 forwards from the relay the subnets file maps to a scope of its
// own, and asserts both halves of what the scope answers with: an address
// from its pool, and the options it sets rather than the ones the top-level
// option plugins set for on-link clients.
func runSubnet4(ctx context.Context, w *world) error {
	msg, err := relayedDiscover(macFor(0x41), w.s.selfRLY4)
	if err != nil {
		return err
	}
	dst := &net.UDPAddr{IP: w.s.serverRLY4.AsSlice(), Port: dhcpv4.ServerPort}
	offer, err := exchange4(ctx, w.v4.relay, dst, msg, isReplyTo(msg, dhcpv4.MessageTypeOffer), replyBudget)
	if err != nil {
		return err
	}

	got := toAddr(offer.YourIPAddr)
	w.note("the relayed client was offered %s, router %s", got, ipsToString(offer.Router()))

	var p problems
	p.truth("the relayed address", w.s.subnetPool4.contains(got),
		fmt.Sprintf("%s is outside %s, the pool the subnet plugin maps to this relay", got, w.s.subnetPool4))
	p.equal("option 3 (router) from the scope", ipsToString(offer.Router()), w.s.subnetRouter4.String())

	// The top-level router plugin is configured with a different gateway, so
	// this also proves the scope overwrote it rather than merely agreeing.
	onLink, _ := w.cfg.Server4.First("router")
	p.truth("the scope's router", ipsToString(offer.Router()) != argsToString(onLink),
		"matches the router plugin's, so the reply does not show which of the two answered")
	return p.err()
}

// runRelayInfo4 forwards a request stamped with the circuit-id the mapping
// file names. The address is outside the scope's pool, so the reply says
// which of the two plugins answered.
func runRelayInfo4(ctx context.Context, w *world) error {
	msg, err := relayedDiscover(macFor(0x42), w.s.selfRLY4, withCircuitID(w.s.circuitID))
	if err != nil {
		return err
	}
	dst := &net.UDPAddr{IP: w.s.serverRLY4.AsSlice(), Port: dhcpv4.ServerPort}
	offer, err := exchange4(ctx, w.v4.relay, dst, msg, isReplyTo(msg, dhcpv4.MessageTypeOffer), replyBudget)
	if err != nil {
		return err
	}
	var p problems
	p.equal("the address mapped to circuit-id "+w.s.circuitID, toAddr(offer.YourIPAddr).String(), w.s.relayinfoAddr4.String())
	p.truth("the mapped address", !w.s.subnetPool4.contains(toAddr(offer.YourIPAddr)),
		"is inside the subnet plugin's pool, so this reply does not prove relayinfo answered")
	return p.err()
}

// runRelayInfoRefused4 sends the same stamped request to the server's
// address on the client-side bridge, so the datagram leaves from this
// container's address there. giaddr still names the allowed relay, so the
// relay plugin passes it; relayinfo matches the source instead and drops it.
func runRelayInfoRefused4(ctx context.Context, w *world) error {
	msg, err := relayedDiscover(macFor(0x43), w.s.selfRLY4, withCircuitID(w.s.circuitID))
	if err != nil {
		return err
	}
	dst := &net.UDPAddr{IP: w.s.serverLAN4.AsSlice(), Port: dhcpv4.ServerPort}
	return silence4(ctx, w.v4.relay, dst, msg, isReplyTo(msg))
}
