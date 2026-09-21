// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// dhcp6 carries the two DHCPv6 sockets.
//
// client is bound to the link-local address of the client-side interface at
// port 546, which is where a DHCPv6 client speaks from, and sends to
// ff02::1:2 with that interface's zone. The zone is not optional: the
// destination is link-local multicast and a host with two bridges has no
// default for it.
//
// relay is an ordinary socket on port 547. A DHCPv6 relay speaks from its
// own address and the server answers the datagram source, so the relay role
// needs nothing raw and nothing link-local.
//
// dhcp6 is not safe for concurrent use; the scenarios run one at a time.
type dhcp6 struct {
	client    *net.UDPConn
	clientMC  *net.UDPAddr
	relay     *net.UDPConn
	iface     *net.Interface
	serverRLY *net.UDPAddr
	serverLAN *net.UDPAddr
}

// newDHCP6 opens both sockets. lan names the client-side interface by the
// global address the compose file pinned on it; the client socket then binds
// that interface's link-local address, the way a real client does.
func newDHCP6(lan, serverLAN, serverRelay netip.Addr) (*dhcp6, error) {
	iface, err := interfaceFor(lan)
	if err != nil {
		return nil, fmt.Errorf("finding the client-side interface: %w", err)
	}
	ll, err := dhcpv6.GetLinkLocalAddr(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("no link-local address on %s: %w; IPv6 has to be enabled on the bridge", iface.Name, err)
	}
	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ll, Port: dhcpv6.DefaultClientPort, Zone: iface.Name})
	if err != nil {
		return nil, fmt.Errorf("binding [%s%%%s]:%d: %w", ll, iface.Name, dhcpv6.DefaultClientPort, err)
	}
	relay, err := net.ListenUDP("udp6", &net.UDPAddr{Port: dhcpv6.DefaultServerPort})
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("binding udp/%d for the relay role: %w; the container needs NET_BIND_SERVICE", dhcpv6.DefaultServerPort, err)
	}
	return &dhcp6{
		client:    client,
		clientMC:  &net.UDPAddr{IP: dhcpv6.AllDHCPRelayAgentsAndServers, Port: dhcpv6.DefaultServerPort, Zone: iface.Name},
		relay:     relay,
		iface:     iface,
		serverLAN: &net.UDPAddr{IP: serverLAN.AsSlice(), Port: dhcpv6.DefaultServerPort},
		serverRLY: &net.UDPAddr{IP: serverRelay.AsSlice(), Port: dhcpv6.DefaultServerPort},
	}, nil
}

func (d *dhcp6) Close() error {
	err := d.client.Close()
	if rerr := d.relay.Close(); err == nil {
		err = rerr
	}
	return err
}

// duidFor builds the DUID-LL a client with this hardware address presents.
// DUID-LL rather than DUID-LLT because it carries the MAC and nothing else,
// which is what lets the file, macfilter, netbox and redis plugins key on a
// hardware address in a family that has no chaddr field.
func duidFor(mac net.HardwareAddr) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}
}

// matcher6 decides whether a received message answers the request at hand.
type matcher6 func(dhcpv6.DHCPv6) bool

// isReplyTo6 matches on the transaction id of the innermost message, so it
// works the same whether the answer came back wrapped in a Relay-reply.
func isReplyTo6(req *dhcpv6.Message, types ...dhcpv6.MessageType) matcher6 {
	return func(got dhcpv6.DHCPv6) bool {
		inner, err := got.GetInnerMessage()
		if err != nil || inner.TransactionID != req.TransactionID {
			return false
		}
		if len(types) == 0 {
			return true
		}
		for _, t := range types {
			if inner.Type() == t {
				return true
			}
		}
		return false
	}
}

// exchange6 sends msg and waits for the first matching answer, resending at
// retryEvery until the budget runs out.
func exchange6(ctx context.Context, pc *net.UDPConn, dst *net.UDPAddr, msg dhcpv6.DHCPv6, match matcher6, budget time.Duration) (dhcpv6.DHCPv6, error) {
	deadline := time.Now().Add(budget)
	nextSend := time.Now()
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(nextSend) {
			continue
		}
		if _, err := pc.WriteTo(msg.ToBytes(), dst); err != nil {
			return nil, fmt.Errorf("sending %s to %s: %w", msg.Type(), dst, err)
		}
		nextSend = time.Now().Add(retryEvery)
		got, ok, err := readUntil6(ctx, pc, match, minTime(nextSend, deadline))
		if err != nil {
			return nil, err
		}
		if ok {
			return got, nil
		}
	}
	return nil, fmt.Errorf("%s: %w after %s", msg.Type(), errNoReply, budget)
}

// silence6 sends msg and fails if anything answers it inside silenceWindow.
func silence6(ctx context.Context, pc *net.UDPConn, dst *net.UDPAddr, msg dhcpv6.DHCPv6, match matcher6) error {
	got, err := exchange6(ctx, pc, dst, msg, match, silenceWindow)
	switch {
	case errors.Is(err, errNoReply):
		return nil
	case err != nil:
		return err
	default:
		return fmt.Errorf("expected no answer, got a %s", got.Type())
	}
}

// readUntil6 reads until a message matches or the deadline passes. The
// boolean is false when the deadline passed with nothing matching, which is
// an outcome rather than a failure: a scenario proving a drop wants it.
func readUntil6(ctx context.Context, pc *net.UDPConn, match matcher6, deadline time.Time) (dhcpv6.DHCPv6, bool, error) {
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := pc.SetReadDeadline(minTime(time.Now().Add(readSlice), deadline)); err != nil {
			return nil, false, fmt.Errorf("setting the read deadline: %w", err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return nil, false, fmt.Errorf("reading from the socket: %w", err)
		}
		msg, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		if match(msg) {
			return msg, true, nil
		}
	}
	return nil, false, nil
}

// wrapRelay6 puts msg inside a Relay-forward the way a relay agent does.
//
// link is the address the relay claims the client is on, which is what the
// subnet plugin selects a scope by, and peer is the client's own link-local.
// ifaceID, when not empty, becomes the interface-id option the relayinfo
// plugin maps to a fixed address.
func wrapRelay6(msg *dhcpv6.Message, link, peer netip.Addr, ifaceID string) (*dhcpv6.RelayMessage, error) {
	rm := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayForward,
		HopCount:    0,
		LinkAddr:    link.AsSlice(),
		PeerAddr:    peer.AsSlice(),
	}
	rm.AddOption(dhcpv6.OptRelayMessage(msg))
	if ifaceID != "" {
		rm.AddOption(dhcpv6.OptInterfaceID([]byte(ifaceID)))
	}
	if _, err := rm.GetInnerMessage(); err != nil {
		return nil, fmt.Errorf("building the Relay-forward: %w", err)
	}
	return rm, nil
}
