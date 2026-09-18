// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package serverid implements a plugin that enforces the server identifier
// on DHCPv4 and DHCPv6 messages: a request explicitly addressed to a
// different server (DHCPv4 option 54, DHCPv6 the ServerID option) is
// dropped rather than answered, and so is a DHCPv4 RELEASE or DECLINE that
// carries no server identifier at all, since RFC 2131 requires one on both.
package serverid

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/server_id")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "server_id",
	Setup6: setup6,
	Setup4: setup4,
}

// pluginState6 holds the DUID a setup6 instance enforces as this server's
// identifier.
type pluginState6 struct {
	serverID dhcpv6.DUID
}

// pluginState4 holds the IP address a setup4 instance enforces as this
// server's identifier.
type pluginState4 struct {
	serverID net.IP
}

// Handler6 handles DHCPv6 packets for the server_id plugin.
func (p *pluginState6) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		// BUG: this should already have failed in the main handler. Abort
		log.Errorf("BUG: cannot read the client message inside the relayed request, dropping it: %v; the client will retry, report this with the server log", err)
		return nil, true
	}

	if sid := msg.Options.ServerID(); sid != nil {
		// RFC8415 §16.{2,5,7}
		// These message types MUST be discarded if they contain *any* ServerID option
		if msg.MessageType == dhcpv6.MessageTypeSolicit ||
			msg.MessageType == dhcpv6.MessageTypeConfirm ||
			msg.MessageType == dhcpv6.MessageTypeRebind {
			return nil, true
		}

		// Approximately all others MUST be discarded if the ServerID doesn't match
		if !sid.Equal(p.serverID) {
			log.Infof("requested server ID does not match this server's ID. Got %v, want %v", sid, p.serverID)
			return nil, true
		}
	} else if msg.MessageType == dhcpv6.MessageTypeRequest ||
		msg.MessageType == dhcpv6.MessageTypeRenew ||
		msg.MessageType == dhcpv6.MessageTypeDecline ||
		msg.MessageType == dhcpv6.MessageTypeRelease {
		// RFC8415 §16.{6,8,10,11}
		// These message types MUST be discarded if they *don't* contain a ServerID option
		return nil, true
	}
	dhcpv6.WithServerID(p.serverID)(resp)
	return resp, false
}

// Handler4 handles DHCPv4 packets for the server_id plugin.
//
// The field that decides whether a request is addressed to this server is
// option 54, the DHCP server identifier (RFC 2131 §4.3.2). A client in
// SELECTING state copies the server identifier from the offer it accepted
// into its DHCPREQUEST, and every other server on the segment is expected to
// stay quiet. siaddr is a different field (the next-server address for
// bootstrapping, e.g. TFTP) that a client may carry over from an earlier
// exchange or leave zero; it says nothing about which DHCP server the
// request is for. Deciding on siaddr instead of option 54 means two servers
// on one segment both answer the same REQUEST, so this handler never looks
// at it.
func (p *pluginState4) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		log.Warningf("request opcode is %s, not BootRequest, passing it on unchanged; check whether a relay or another DHCP server is looping replies back here", req.OpCode)
		return resp, false
	}
	sid := req.ServerIdentifier()
	if sid == nil && requiresServerID(req.MessageType()) {
		// RFC 2131 Table 5 makes option 54 a MUST on RELEASE and DECLINE:
		// both are unicast to the server that owns the lease, so one with
		// no server identifier (or a malformed option 54, which
		// ServerIdentifier also reports as nil) cannot be shown to be
		// addressed to us and is dropped like a mismatch would be.
		log.Infof("%s with no server identifier, dropping", req.MessageType())
		return nil, true
	}
	if sid != nil && !sid.Equal(p.serverID) {
		// This request is for a different server, drop it.
		log.Infof("requested server ID does not match this server's ID. Got %v, want %v", sid, p.serverID)
		return nil, true
	}
	resp.ServerIPAddr = make(net.IP, net.IPv4len)
	copy(resp.ServerIPAddr[:], p.serverID)
	resp.UpdateOption(dhcpv4.OptServerIdentifier(p.serverID))
	return resp, false
}

// requiresServerID reports whether RFC 2131 Table 5 requires message type t
// to carry option 54. RELEASE and DECLINE are unicast to the server that
// owns the lease, so a message of either type is meaningless without one.
func requiresServerID(t dhcpv4.MessageType) bool {
	return t == dhcpv4.MessageTypeRelease || t == dhcpv4.MessageTypeDecline
}

func setup4(args ...string) (handler.Handler4, error) {
	log.Printf("loading `server_id` plugin for DHCPv4 with args: %v", args)
	if len(args) < 1 {
		return nil, errors.New("no server identifier given; pass this server's IPv4 address, for example 10.0.0.1")
	}
	serverID := net.ParseIP(args[0])
	if serverID == nil {
		return nil, fmt.Errorf("argument %q is not an IP address; pass this server's IPv4 address, for example 10.0.0.1", args[0])
	}
	if serverID.To4() == nil {
		return nil, fmt.Errorf("argument %q is not an IPv4 address; under server4 the server identifier is a dotted address such as 10.0.0.1", args[0])
	}
	p := pluginState4{serverID: serverID.To4()}
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	log.Printf("loading `server_id` plugin for DHCPv6 with args: %v", args)
	if len(args) < 2 {
		return nil, fmt.Errorf("need a DUID type and a link-layer address, got %d argument(s); write them as two arguments, for example LL aa:bb:cc:dd:ee:ff", len(args))
	}
	duidType := args[0]
	if duidType == "" {
		return nil, errors.New("the DUID type argument is empty; use LL or LLT, for example LL aa:bb:cc:dd:ee:ff")
	}
	duidValue := args[1]
	if duidValue == "" {
		return nil, errors.New("the DUID value argument is empty; give a link-layer address, for example LL aa:bb:cc:dd:ee:ff")
	}
	duidType = strings.ToLower(duidType)
	hwaddr, err := net.ParseMAC(duidValue)
	if err != nil {
		return nil, fmt.Errorf("DUID value %q is not a MAC address: %w; write it as six octets, for example aa:bb:cc:dd:ee:ff", duidValue, err)
	}
	p := pluginState6{}
	switch duidType {
	case "ll", "duid-ll", "duid_ll":
		p.serverID = &dhcpv6.DUIDLL{
			// sorry, only ethernet for now
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: hwaddr,
		}
	case "llt", "duid-llt", "duid_llt":
		p.serverID = &dhcpv6.DUIDLLT{
			// sorry, zero-time for now
			Time: 0,
			// sorry, only ethernet for now
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: hwaddr,
		}
	case "en", "uuid":
		return nil, fmt.Errorf("DUID type %q is not supported yet; use LL or LLT, for example LL aa:bb:cc:dd:ee:ff", args[0])
	default:
		return nil, fmt.Errorf("DUID type %q is not recognised; use LL or LLT (also spelled duid-ll and duid-llt), for example LL aa:bb:cc:dd:ee:ff", args[0])
	}
	log.Printf("using %s %s", duidType, duidValue)

	return p.Handler6, nil
}
