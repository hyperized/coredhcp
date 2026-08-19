// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
)

// sendEthernetFn is swappable so the layer-2 reply path can be exercised in
// tests without a raw socket.
var sendEthernetFn = sendEthernet

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

// applyHandlers6 walks the plugin chain. A nil result means the request is
// dropped.
func applyHandlers6(handlers []handler.Handler6, req, resp dhcpv6.DHCPv6) dhcpv6.DHCPv6 {
	for _, h := range handlers {
		var stop bool
		resp, stop = h(req, resp)
		if stop {
			break
		}
	}
	return resp
}

// applyHandlers4 walks the plugin chain. A nil result means the request is
// dropped.
func applyHandlers4(handlers []handler.Handler4, req, resp *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	for _, h := range handlers {
		var stop bool
		resp, stop = h(req, resp)
		if stop {
			break
		}
	}
	return resp
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

// replyDestination4 decides where a DHCPv4 response goes. useEthernet is set
// when the client has no usable IP yet and the reply must leave as a raw
// layer-2 unicast.
func replyDestination4(req, resp *dhcpv4.DHCPv4) (peer *net.UDPAddr, useEthernet bool) {
	switch {
	case !req.GatewayIPAddr.IsUnspecified():
		// TODO: make RFC8357 compliant
		return &net.UDPAddr{IP: req.GatewayIPAddr, Port: dhcpv4.ServerPort}, false
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

// HandleMsg6 runs for every received DHCPv6 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
func (l *listener6) HandleMsg6(buf []byte, oob *ipv6.ControlMessage, peer *net.UDPAddr) {
	req, err := dhcpv6.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv6 request: %v", err)
		return
	}

	resp, err := buildReply6(req)
	if err != nil {
		log.Warningf("MainHandler6: %v", err)
		return
	}

	resp = applyHandlers6(l.handlers, req, resp)
	if resp == nil {
		log.Print("MainHandler6: dropping request because response is nil")
		return
	}

	resp, err = encapsulateRelay6(req, resp)
	if err != nil {
		log.Warningf("DHCPv6: cannot create relay-repl from relay-forw: %v", err)
		return
	}

	var woob *ipv6.ControlMessage
	if peer.IP.IsLinkLocalUnicast() {
		// LL need to be directed to the correct interface. Globally reachable
		// addresses should use the default route, in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex6(oob)); idx != 0 {
			woob = &ipv6.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg6: Did not receive interface information")
		}
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Printf("MainHandler6: conn.Write to %v failed: %v", peer, err)
	}
}

// HandleMsg4 runs for every received DHCPv4 packet. It will run every
// registered handler in sequence, and reply with the resulting response.
// It will not reply if the resulting response is `nil`.
func (l *listener4) HandleMsg4(buf []byte, oob *ipv4.ControlMessage, _ net.Addr) {
	req, err := dhcpv4.FromBytes(buf)
	bufpool.Put(&buf)
	if err != nil {
		log.Printf("Error parsing DHCPv4 request: %v", err)
		return
	}

	resp, err := buildReply4(req)
	if err != nil {
		log.Printf("MainHandler4: %v", err)
		return
	}

	resp = applyHandlers4(l.handlers, req, resp)
	if resp == nil {
		log.Print("MainHandler4: dropping request because response is nil")
		return
	}

	peer, useEthernet := replyDestination4(req, resp)

	var woob *ipv4.ControlMessage
	if peer.IP.Equal(net.IPv4bcast) || peer.IP.IsLinkLocalUnicast() || useEthernet {
		// Direct broadcasts, link-local and layer2 unicasts to the interface
		// the request was received on. Other packets should use the normal
		// routing table in case of asymetric routing.
		if idx := replyIfIndex(l.Index, oobIfIndex4(oob)); idx != 0 {
			woob = &ipv4.ControlMessage{IfIndex: idx}
		} else {
			log.Errorf("HandleMsg4: Did not receive interface information")
		}
	}

	if useEthernet {
		if woob == nil {
			// Without an interface there is nothing to put the frame on;
			// dereferencing woob here used to crash the server.
			log.Errorf("MainHandler4: cannot send layer-2 reply without interface information")
			return
		}
		intf, err := net.InterfaceByIndex(woob.IfIndex)
		if err != nil {
			log.Errorf("MainHandler4: Can not get Interface for index %d %v", woob.IfIndex, err)
			return
		}
		if err := sendEthernetFn(*intf, resp); err != nil {
			log.Errorf("MainHandler4: Cannot send Ethernet packet: %v", err)
		}
		return
	}
	if _, err := l.WriteTo(resp.ToBytes(), woob, peer); err != nil {
		log.Errorf("MainHandler4: conn.Write to %v failed: %v", peer, err)
	}
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

// XXX: performance-wise, Pool may or may not be good (see https://github.com/golang/go/issues/23199)
// Interface is good for what we want. Maybe "just" trust the GC and we'll be fine ?
var bufpool = sync.Pool{New: func() interface{} { r := make([]byte, MaxDatagram); return &r }}

// MaxDatagram is the maximum length of message that can be received.
const MaxDatagram = 1 << 16

// XXX: investigate using RecvMsgs to batch messages and reduce syscalls

// Serve handles datagrams received on the DHCPv6 connection and passes them
// to the plugin chain.
func (l *listener6) Serve() error {
	log.Printf("Listen %s", l.LocalAddr())
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] // Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.ReadFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go l.HandleMsg6(b[:n], oob, peer.(*net.UDPAddr))
	}
}

// Serve handles datagrams received on the DHCPv4 connection and passes them
// to the plugin chain.
func (l *listener4) Serve() error {
	log.Printf("Listen %s", l.LocalAddr())
	for {
		b := *bufpool.Get().(*[]byte)
		b = b[:MaxDatagram] // Reslice to max capacity in case the buffer in pool was resliced smaller

		n, oob, peer, err := l.ReadFrom(b)
		if errors.Is(err, net.ErrClosed) {
			// Server is quitting
			return nil
		} else if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		go l.HandleMsg4(b[:n], oob, peer.(*net.UDPAddr))
	}
}
