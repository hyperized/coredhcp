// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/plugins"
)

// buildReply6 decapsulates a possibly-relayed request and builds the base
// response that the plugin chain will decorate.
func buildReply6(d dhcpv6.DHCPv6) (dhcpv6.DHCPv6, error) {
	msg, err := d.GetInnerMessage()
	if err != nil {
		return nil, fmt.Errorf("cannot get inner message: %w", err)
	}
	switch msg.Type() {
	case dhcpv6.MessageTypeSolicit:
		if msg.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
			return dhcpv6.NewReplyFromMessage(msg)
		}
		return dhcpv6.NewAdvertiseFromSolicit(msg)
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew,
		dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeInformationRequest:
		return dhcpv6.NewReplyFromMessage(msg)
	case dhcpv6.MessageTypeDecline:
		// A Decline is answered with a Reply, unlike its DHCPv4 namesake
		// which gets nothing at all: RFC 8415 section 18.3.8.
		return replyToDecline6(msg)
	default:
		return nil, fmt.Errorf("message type %d not supported", msg.Type())
	}
}

// replyToDecline6 builds the base Reply for a DHCPv6 Decline.
//
// dhcpv6.NewReplyFromMessage will not build one: its switch lists every
// request type except Decline, and returns "cannot create REPLY from the
// passed message type set" for it (dhcpv6/dhcpv6message.go). The reply it
// would produce for a Release is just the transaction ID and the client's
// DUID, so that is what this makes. Drop it once upstream accepts Decline.
func replyToDecline6(msg *dhcpv6.Message) (dhcpv6.DHCPv6, error) {
	cid := msg.GetOneOption(dhcpv6.OptionClientID)
	if cid == nil {
		return nil, errors.New("client ID cannot be nil when building a Reply to a Decline")
	}
	rep := &dhcpv6.Message{
		MessageType:   dhcpv6.MessageTypeReply,
		TransactionID: msg.TransactionID,
	}
	rep.AddOption(cid)
	return rep, nil
}

// buildReply4 validates the request and builds the base response that the
// plugin chain will decorate.
func buildReply4(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		return nil, fmt.Errorf("unsupported opcode %d, only BootRequest (%d) is supported", req.OpCode, dhcpv4.OpcodeBootRequest)
	}
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build reply: %w", err)
	}
	switch mt := req.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	case dhcpv4.MessageTypeRequest, dhcpv4.MessageTypeInform:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	case dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		// Neither takes a reply (RFC 2131 section 4.4), so no message
		// type is set here and HandleMsg4 sends nothing. The base reply
		// still exists because the chain runs: plugins free or
		// quarantine the lease, and some carry state on the response.
	default:
		return nil, fmt.Errorf("unhandled message type: %v", mt)
	}
	return resp, nil
}

// takesNoReply4 reports whether a DHCPv4 message type is one the server never
// answers. RFC 2131 section 4.4: a client sends RELEASE to hand an address
// back and DECLINE to say the address it was offered is already in use, and
// neither exchange contains a message from the server. The chain still runs
// for both so a plugin can free or quarantine the lease; whatever it hands
// back is discarded.
func takesNoReply4(mt dhcpv4.MessageType) bool {
	return mt == dhcpv4.MessageTypeRelease || mt == dhcpv4.MessageTypeDecline
}

// applyHandlers6 walks the plugin chain. A nil response means the request is
// dropped. stoppedAt is the position of the link that stopped the chain, or
// -1 when every plugin ran; the links are indexed rather than ranged over so
// the loop does not copy a Link6 per plugin per packet.
func applyHandlers6(chain []plugins.Link6, req, resp dhcpv6.DHCPv6) (_ dhcpv6.DHCPv6, stoppedAt int) {
	for i := range chain {
		var stop bool
		resp, stop = chain[i].Handler(req, resp)
		if stop {
			return resp, i
		}
	}
	return resp, -1
}

// applyHandlers4 walks the plugin chain. A nil response means the request is
// dropped. stoppedAt is the position of the link that stopped the chain, or
// -1 when every plugin ran.
func applyHandlers4(chain []plugins.Link4, req, resp *dhcpv4.DHCPv4) (_ *dhcpv4.DHCPv4, stoppedAt int) {
	for i := range chain {
		var stop bool
		resp, stop = chain[i].Handler(req, resp)
		if stop {
			return resp, i
		}
	}
	return resp, -1
}

// encapsulateRelay6 re-wraps the response for the relay chain the request
// came through. Responses that are not plain messages pass through
// unchanged.
func encapsulateRelay6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, error) {
	if !req.IsRelay() {
		return resp, nil
	}
	rmsg, ok := resp.(*dhcpv6.Message)
	if !ok {
		log.Warningf("DHCPv6: response is a relayed message, not reencapsulating")
		return resp, nil
	}
	return dhcpv6.NewRelayReplFromRelayForw(req.(*dhcpv6.RelayMessage), rmsg)
}

// replyDestination4 decides where a DHCPv4 response goes. src is the address
// the request arrived from (may be nil when unknown). useEthernet is set when
// the client has no usable IP yet and the reply must leave as a raw layer-2
// unicast.
func replyDestination4(req, resp *dhcpv4.DHCPv4, src *net.UDPAddr) (peer *net.UDPAddr, useEthernet bool) {
	switch {
	case !req.GatewayIPAddr.IsUnspecified():
		// RFC 8357: a relay may send from a port other than 67, and the
		// reply must go back to the port the request came from.
		port := dhcpv4.ServerPort
		if src != nil && src.Port != 0 {
			port = src.Port
		}
		return &net.UDPAddr{IP: req.GatewayIPAddr, Port: port}, false
	case resp.MessageType() == dhcpv4.MessageTypeNak:
		return &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}, false
	case !req.ClientIPAddr.IsUnspecified():
		return &net.UDPAddr{IP: req.ClientIPAddr, Port: dhcpv4.ClientPort}, false
	case req.IsBroadcast():
		return &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}, false
	default:
		// send a layer-2 frame so that we can define the destination MAC address
		return &net.UDPAddr{IP: resp.YourIPAddr, Port: dhcpv4.ClientPort}, true
	}
}

// replyIfIndex picks the interface a reply leaves through: the listener's
// bound interface if any, otherwise the interface the request came in on,
// otherwise 0 (unknown, use the routing table).
func replyIfIndex(bound, oob int) int {
	if bound != 0 {
		return bound
	}
	return oob
}

// oobIfIndex6 extracts the incoming interface index from per-packet control
// data, 0 if absent.
func oobIfIndex6(oob *ipv6.ControlMessage) int {
	if oob != nil {
		return oob.IfIndex
	}
	return 0
}

// oobIfIndex4 extracts the incoming interface index from per-packet control
// data, 0 if absent.
func oobIfIndex4(oob *ipv4.ControlMessage) int {
	if oob != nil {
		return oob.IfIndex
	}
	return 0
}
