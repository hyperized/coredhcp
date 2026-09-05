// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package events describes what the server reports about its own activity:
// listeners bound, plugins loaded, and every request handled.
//
// A plugin only ever sees its own position in the chain, while the server
// sees the outcome of every packet. Nothing here imports the DHCP libraries,
// so an observer works on plain values it can construct in a test.
package events

import (
	"net/netip"
	"time"
)

// Family is the protocol family a listener, plugin or request belongs to.
type Family uint8

// The two protocol families the server speaks.
const (
	FamilyV4 Family = 4
	FamilyV6 Family = 6
)

// String renders the family as "DHCPv4" or "DHCPv6".
func (f Family) String() string {
	switch f {
	case FamilyV4:
		return "DHCPv4"
	case FamilyV6:
		return "DHCPv6"
	default:
		return "DHCP?"
	}
}

// Outcome is what happened to a request.
type Outcome uint8

// The outcomes a request can reach.
const (
	// OutcomeReplied means a reply left the server.
	OutcomeReplied Outcome = iota
	// OutcomeDropped means the chain returned no response, so nothing was sent.
	OutcomeDropped
	// OutcomeNoReply means the message type takes no reply whatever the chain
	// returns: DHCPv4 RELEASE and DECLINE, RFC 2131 section 4.4.
	OutcomeNoReply
	// OutcomeParseError means the datagram did not decode as DHCP. Only Time,
	// Family, Interface, Peer and Error are set.
	OutcomeParseError
	// OutcomeUnsupported means the packet decoded but has no reply: unknown
	// opcode or message type, or a relay message that would not re-encapsulate.
	OutcomeUnsupported
	// OutcomeSendError means a reply was built but could not be sent.
	OutcomeSendError
)

// String renders the outcome as a short lower-case word for display.
func (o Outcome) String() string {
	switch o {
	case OutcomeReplied:
		return "replied"
	case OutcomeDropped:
		return "dropped"
	case OutcomeNoReply:
		return "no reply"
	case OutcomeParseError:
		return "parse error"
	case OutcomeUnsupported:
		return "unsupported"
	case OutcomeSendError:
		return "send error"
	default:
		return "unknown"
	}
}

// ReplyPath is how a reply left the server.
type ReplyPath uint8

// The reply paths. DHCPv6 is always unicast; DHCPv4 picks one of three
// depending on what the client can already receive.
const (
	// PathNone means no reply was sent.
	PathNone ReplyPath = iota
	// PathUnicast is a UDP datagram to the peer, relay or current address.
	PathUnicast
	// PathBroadcast is for DHCPv4 clients that asked for it or got a NAK.
	PathBroadcast
	// PathLayer2 is a raw Ethernet frame, for a client with no usable address.
	PathLayer2
)

// String renders the path as a short word for display.
func (p ReplyPath) String() string {
	switch p {
	case PathNone:
		return "-"
	case PathUnicast:
		return "unicast"
	case PathBroadcast:
		return "broadcast"
	case PathLayer2:
		return "layer2"
	default:
		return "unknown"
	}
}

// Request is one request the server handled and what became of it.
// Which fields are set depends on Outcome; anything undetermined stays zero.
type Request struct {
	// Time is when the datagram was read from the socket.
	Time time.Time
	// Family is the protocol family of the listener that received it.
	Family Family
	// Interface is empty when the socket did not report one.
	Interface string
	// Peer is the source address of the datagram.
	Peer netip.AddrPort
	// Relay is giaddr on DHCPv4, the outermost relay's link address on DHCPv6.
	// Zero for a request straight from the client.
	Relay netip.Addr

	// Type is the message type as the DHCP library names it. For a relayed
	// DHCPv6 message it is the inner message's type.
	Type string
	// ReplyType is empty when nothing was sent.
	ReplyType string
	// ClientID is the hardware address on DHCPv4, the DUID in hex on DHCPv6.
	ClientID string
	// Hostname is option 12 on DHCPv4, the FQDN option on DHCPv6.
	Hostname string

	// Addresses is yiaddr as a /32 on DHCPv4; on DHCPv6 every IA_NA and IA_TA
	// address as a /128, plus every IA_PD prefix as given.
	Addresses []netip.Prefix
	// LeaseTime is option 51 on DHCPv4, the shortest valid lifetime on DHCPv6.
	LeaseTime time.Duration

	Outcome Outcome
	// Plugin is empty when every plugin ran. Set for replies as well as drops.
	Plugin string
	// Position is 1-based, 0 when every plugin ran. A plugin can be configured
	// twice, so the name alone does not identify the link.
	Position int
	// Path is PathNone when no reply left.
	Path ReplyPath
	// Duration is the time spent in the plugin chain, not the whole exchange.
	Duration time.Duration
	// Error is set only for the error outcomes.
	Error string
}

// Listener is a socket the server bound.
type Listener struct {
	Family Family
	// Address is in host:port form, e.g. "[::]:547".
	Address string
	// Interface is empty when the socket listens on all of them.
	Interface string
}

// Plugin is one entry of a family's handler chain, in chain order.
type Plugin struct {
	Family Family
	// Name is the plugin name as configured.
	Name string
	// Args have the credential forms config.RedactArgs knows about replaced by
	// "***", but a plugin may still take a secret in a shape it misses.
	Args []string
}

// Observer receives the server's events.
// Request runs on the packet's critical path from many goroutines at once, so
// an implementation must be safe for concurrent use and must not block.
type Observer interface {
	Listener(Listener)
	Plugin(Plugin)
	Request(Request)
}
