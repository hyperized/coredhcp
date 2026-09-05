// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/plugins"
)

// buildReply6 decapsulates a relayed request and builds the base response.
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

// dhcpv6.NewReplyFromMessage refuses a Decline, so the Release-shaped reply
// it would build (transaction ID plus client DUID) is assembled here instead.
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

// buildReply4 validates the request and builds the base response.
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
		// No message type set: RFC 2131 section 4.4 answers neither, but the
		// chain still runs so a plugin can free or quarantine the lease.
	default:
		return nil, fmt.Errorf("unhandled message type: %v", mt)
	}
	return resp, nil
}

// takesNoReply4 reports the types the server never answers, RFC 2131 section
// 4.4. The chain still runs for both; whatever it returns is discarded.
func takesNoReply4(mt dhcpv4.MessageType) bool {
	return mt == dhcpv4.MessageTypeRelease || mt == dhcpv4.MessageTypeDecline
}

// applyHandlers6 walks the chain, returning -1 when every plugin ran and a nil
// response when it is dropped. Indexed, so no Link6 is copied per packet.
func applyHandlers6(ctx context.Context, chain []plugins.Link6, req, resp dhcpv6.DHCPv6) (_ dhcpv6.DHCPv6, stoppedAt int) {
	for i := range chain {
		var stop bool
		resp, stop = chain[i].Handler(ctx, req, resp)
		if stop {
			return resp, i
		}
	}
	return resp, -1
}

// applyHandlers4 walks the chain, returning -1 when every plugin ran.
func applyHandlers4(ctx context.Context, chain []plugins.Link4, req, resp *dhcpv4.DHCPv4) (_ *dhcpv4.DHCPv4, stoppedAt int) {
	for i := range chain {
		var stop bool
		resp, stop = chain[i].Handler(ctx, req, resp)
		if stop {
			return resp, i
		}
	}
	return resp, -1
}

// encapsulateRelay6 re-wraps the response for the relay chain it came through.
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

// replyDestination4 decides where a DHCPv4 response goes. useEthernet is set
// when the client has no address yet and the reply has to leave at layer 2.
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
		// Layer 2, so the destination MAC can be set explicitly.
		return &net.UDPAddr{IP: resp.YourIPAddr, Port: dhcpv4.ClientPort}, true
	}
}

// replyIfIndex returns 0 when neither is known, meaning use the routing table.
func replyIfIndex(bound, oob int) int {
	if bound != 0 {
		return bound
	}
	return oob
}

func oobIfIndex6(oob *ipv6.ControlMessage) int {
	if oob != nil {
		return oob.IfIndex
	}
	return 0
}

func oobIfIndex4(oob *ipv4.ControlMessage) int {
	if oob != nil {
		return oob.IfIndex
	}
	return 0
}
