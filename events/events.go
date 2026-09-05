// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package events describes what the server reports about its own activity:
// listeners it bound, plugins it loaded, and every request it handled with
// the reply that went out for it.
//
// A plugin in the handler chain only sees the response at its own position,
// and a plugin ahead of it that stops the chain hides the request from it
// entirely. The server, on the other hand, knows the outcome of every packet
// at the point where it sends or drops the reply. That is where these events
// come from, so an observer such as the terminal UI can show what was issued
// and what was confirmed without sitting in the chain.
//
// Nothing here imports the DHCP libraries on purpose: an observer works on
// plain values it can construct in tests, and the server does the
// translation from packets.
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

// String renders the family the way the rest of the code base names it in
// log lines: "DHCPv4" or "DHCPv6".
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

// The outcomes, in the order the server can reach them while handling a
// packet.
const (
	// OutcomeReplied means a reply left the server.
	OutcomeReplied Outcome = iota
	// OutcomeDropped means the plugin chain returned no response, so
	// nothing was sent. Plugin names the plugin that stopped the chain
	// when one did.
	OutcomeDropped
	// OutcomeNoReply means the message type takes no reply at all: the
	// chain ran, and nothing was sent whatever it returned. DHCPv4 RELEASE
	// and DECLINE are the two, see RFC 2131 section 4.4. Plugin and
	// Position are set when a plugin stopped the chain.
	OutcomeNoReply
	// OutcomeParseError means the datagram was not a DHCP packet the
	// library could decode. Only Time, Family, Interface, Peer and Error
	// are set.
	OutcomeParseError
	// OutcomeUnsupported means the packet decoded but the server has no
	// reply for its opcode or message type, or a DHCPv6 relay message could
	// not be re-encapsulated. Type is set when it could be read.
	OutcomeUnsupported
	// OutcomeSendError means a reply was built but could not be sent. Error
	// carries the reason; ReplyType and Path say what was attempted.
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

// The reply paths. DHCPv6 replies are always unicast to the peer; DHCPv4 has
// three ways out depending on what the client can already receive.
const (
	// PathNone means no reply was sent.
	PathNone ReplyPath = iota
	// PathUnicast is a UDP datagram to the peer, the relay or the client's
	// current address.
	PathUnicast
	// PathBroadcast is a UDP datagram to 255.255.255.255, for DHCPv4 clients
	// that asked for it or that received a NAK.
	PathBroadcast
	// PathLayer2 is a raw Ethernet frame to the client's hardware address,
	// for DHCPv4 clients that have no usable address yet.
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
//
// Which fields are set depends on Outcome; see the outcome constants. A
// field the server could not determine is left at its zero value rather
// than guessed.
type Request struct {
	// Time is when the datagram was read from the socket.
	Time time.Time
	// Family is the protocol family of the listener that received it.
	Family Family
	// Interface is the name of the interface the request arrived on, empty
	// when the listener is not bound to one and the socket did not say.
	Interface string
	// Peer is the source address of the datagram.
	Peer netip.AddrPort
	// Relay is the relay agent's address when the request came through
	// one: giaddr on DHCPv4, the outermost relay's link address on DHCPv6.
	// Zero for requests straight from the client.
	Relay netip.Addr

	// Type is the request's message type as the DHCP library names it,
	// e.g. "DISCOVER" or "SOLICIT". For a relayed DHCPv6 message this is
	// the inner message's type.
	Type string
	// ReplyType is the message type of the reply that was sent, e.g.
	// "OFFER" or "REPLY". Empty when nothing was sent.
	ReplyType string
	// ClientID identifies the client: the hardware address on DHCPv4, the
	// DUID in hex on DHCPv6. Empty when the packet could not be parsed.
	ClientID string
	// Hostname is the name the client sent, if any: option 12 on DHCPv4,
	// the FQDN option on DHCPv6.
	Hostname string

	// Addresses is what the reply handed out. On DHCPv4 it is yiaddr as a
	// /32 when set. On DHCPv6 it is every IA_NA and IA_TA address as a /128
	// and every IA_PD prefix as given. Nil when the reply carried none.
	Addresses []netip.Prefix
	// LeaseTime is how long the addresses are good for: option 51 on
	// DHCPv4, the shortest valid lifetime on DHCPv6. Zero when absent.
	LeaseTime time.Duration

	// Outcome is what happened to the request.
	Outcome Outcome
	// Plugin is the name of the plugin that stopped the chain, empty when
	// every plugin ran. Set for both replies and drops.
	Plugin string
	// Position is the 1-based place in the chain of the plugin that stopped
	// it, 0 when every plugin ran. A plugin can be configured more than
	// once, so this is what tells the two apart.
	Position int
	// Path is how the reply left, PathNone when it did not.
	Path ReplyPath
	// Duration is the time spent in the plugin chain.
	Duration time.Duration
	// Error is the error text for the error outcomes, empty otherwise.
	Error string
}

// Listener is a socket the server bound.
type Listener struct {
	// Family is the protocol family served on it.
	Family Family
	// Address is the bound address in host:port form, e.g. "[::]:547".
	Address string
	// Interface is the interface it is bound to, empty when it listens on
	// all of them.
	Interface string
}

// Plugin is one entry of a family's handler chain, in chain order.
type Plugin struct {
	// Family is the chain it was loaded into.
	Family Family
	// Name is the plugin name as configured.
	Name string
	// Args are the plugin's arguments as configured, with the credential
	// forms the server knows about replaced by "***": see
	// config.RedactArgs for which those are. A plugin can still take a
	// secret in a shape the server does not recognise, so observers should
	// not write these anywhere they would not write a password.
	Args []string
}

// Observer receives the server's events.
//
// Listener and Plugin are called from the goroutine that starts the server,
// before any request arrives. Request is called from the goroutine handling
// that packet, so many calls can be in flight at once: implementations must
// be safe for concurrent use and must not block, because they run on the
// packet's critical path.
type Observer interface {
	Listener(Listener)
	Plugin(Plugin)
	Request(Request)
}
