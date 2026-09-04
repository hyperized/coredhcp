// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
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
	default:
		return nil, fmt.Errorf("message type %d not supported", msg.Type())
	}
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
	case dhcpv4.MessageTypeRelease:
		// no response type to set; plugins decide whether to answer
	default:
		return nil, fmt.Errorf("unhandled message type: %v", mt)
	}
	return resp, nil
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
