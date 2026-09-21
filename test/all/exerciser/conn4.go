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

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// rawUDPConn is the on-link DHCPv4 socket: a packet conn that puts a whole
// UDP datagram on the wire and can be asked for a second writer with a
// different IP source address. openRawUDP builds one, and only on Linux.
type rawUDPConn interface {
	net.PacketConn

	// withSource returns a write-only view of the same socket whose
	// datagrams carry src as their IP source address.
	withSource(src netip.Addr) net.PacketConn
}

const (
	// replyBudget is how long one exchange may take before it counts as no
	// answer. Everything here is one hop across a bridge, so a reply that has
	// not arrived in two seconds is not coming.
	replyBudget = 2 * time.Second

	// silenceWindow is how long a scenario waits to be sure a request really
	// was dropped. Longer than replyBudget, because proving a negative is
	// worth more patience than proving a positive.
	silenceWindow = 3 * time.Second

	// retryEvery is how often an unanswered request is sent again inside the
	// budget, so one lost frame on the bridge does not fail a scenario.
	retryEvery = 700 * time.Millisecond

	// readSlice bounds one blocking read, so the loops below notice the
	// overall deadline and the context without a watchdog goroutine.
	readSlice = 100 * time.Millisecond
)

// errNoReply is what an exchange returns when the budget ran out. Scenarios
// that expect a drop match on it rather than on the message text.
var errNoReply = errors.New("no reply within the budget")

// dhcp4 carries the two DHCPv4 sockets the exerciser needs.
//
// onLink is a raw AF_PACKET socket on the client-side bridge. It has to be
// raw: the server answers a client that holds no address with a layer 2
// unicast, and a client that sets the broadcast flag with a UDP broadcast,
// and neither reaches an ordinary socket on an interface that does not own
// the address in question.
//
// relay is an ordinary UDP socket bound to port 67 on every interface. In
// the relay role the exerciser is a host with an address of its own, and the
// server sends its answer to giaddr at the source port of the request, so
// one socket on port 67 covers both bridges and both directions.
//
// dhcp4 is not safe for concurrent use; the scenarios run one at a time.
type dhcp4 struct {
	onLink rawUDPConn
	relay  *net.UDPConn
	iface  *net.Interface
}

// newDHCP4 opens both sockets. lan is the address the compose file pinned on
// the client-side bridge, and names the interface the raw socket binds to.
func newDHCP4(lan netip.Addr) (*dhcp4, error) {
	iface, err := interfaceFor(lan)
	if err != nil {
		return nil, fmt.Errorf("finding the client-side interface: %w", err)
	}
	onLink, err := openRawUDP(iface.Name, dhcpv4.ClientPort)
	if err != nil {
		return nil, err
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{Port: dhcpv4.ServerPort})
	if err != nil {
		_ = onLink.Close()
		return nil, fmt.Errorf("binding udp/%d for the relay role: %w; the container needs NET_BIND_SERVICE", dhcpv4.ServerPort, err)
	}
	return &dhcp4{onLink: onLink, relay: relay, iface: iface}, nil
}

func (d *dhcp4) Close() error {
	err := d.onLink.Close()
	if rerr := d.relay.Close(); err == nil {
		err = rerr
	}
	return err
}

// serverBroadcast is where an on-link client sends: the all-ones address at
// the server port, which the raw socket puts on the wire as an Ethernet
// broadcast.
var serverBroadcast = &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ServerPort}

// matcher decides whether a received message answers the request at hand.
type matcher func(*dhcpv4.DHCPv4) bool

// isReplyTo matches on the transaction id, which is what tells our own
// exchange apart from every other client's traffic on the same bridge.
func isReplyTo(req *dhcpv4.DHCPv4, types ...dhcpv4.MessageType) matcher {
	return func(got *dhcpv4.DHCPv4) bool {
		if got.TransactionID != req.TransactionID {
			return false
		}
		if len(types) == 0 {
			return true
		}
		for _, t := range types {
			if got.MessageType() == t {
				return true
			}
		}
		return false
	}
}

// exchange sends req and waits for the first message that matches, resending
// at retryEvery until the budget runs out.
func exchange4(ctx context.Context, pc net.PacketConn, dst net.Addr, req *dhcpv4.DHCPv4, match matcher, budget time.Duration) (*dhcpv4.DHCPv4, error) {
	deadline := time.Now().Add(budget)
	nextSend := time.Now()
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(nextSend) {
			continue
		}
		if _, err := pc.WriteTo(req.ToBytes(), dst); err != nil {
			return nil, fmt.Errorf("sending %s to %s: %w", req.MessageType(), dst, err)
		}
		nextSend = time.Now().Add(retryEvery)
		got, ok, err := readUntil4(ctx, pc, match, minTime(nextSend, deadline))
		if err != nil {
			return nil, err
		}
		if ok {
			return got, nil
		}
	}
	return nil, fmt.Errorf("%s: %w after %s", req.MessageType(), errNoReply, budget)
}

// send4 puts one message on the wire and does not wait for anything.
func send4(pc net.PacketConn, dst net.Addr, req *dhcpv4.DHCPv4) error {
	if _, err := pc.WriteTo(req.ToBytes(), dst); err != nil {
		return fmt.Errorf("sending %s to %s: %w", req.MessageType(), dst, err)
	}
	return nil
}

// silence4 sends req and fails if anything answers it inside silenceWindow.
// It resends the way exchange4 does, so a scenario cannot pass because the
// single request it sent was lost rather than dropped on purpose.
func silence4(ctx context.Context, pc net.PacketConn, dst net.Addr, req *dhcpv4.DHCPv4, match matcher) error {
	got, err := exchange4(ctx, pc, dst, req, match, silenceWindow)
	switch {
	case errors.Is(err, errNoReply):
		return nil
	case err != nil:
		return err
	default:
		return fmt.Errorf("expected no answer, got a %s carrying %s", got.MessageType(), got.YourIPAddr)
	}
}

// readUntil4 reads until a message matches or the deadline passes. The
// boolean is false when the deadline passed with nothing matching, which is
// an outcome rather than a failure: a scenario proving a drop wants it.
func readUntil4(ctx context.Context, pc net.PacketConn, match matcher, deadline time.Time) (*dhcpv4.DHCPv4, bool, error) {
	buf := make([]byte, 1500)
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
		// Anything that does not decode is another client's traffic or
		// padding the raw socket handed up, never a reason to fail.
		msg, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		if match(msg) {
			return msg, true, nil
		}
	}
	return nil, false, nil
}

// countReplies4 sends every message in reqs as fast as the socket takes them
// and then counts how many of them were answered. It is how the rate limiter
// is observed: the plugin drops silently and the counters it moves are the
// ones that count requests received, not requests served.
func countReplies4(ctx context.Context, pc net.PacketConn, dst net.Addr, reqs []*dhcpv4.DHCPv4, drain time.Duration) (sent, answered int, err error) {
	wanted := make(map[dhcpv4.TransactionID]bool, len(reqs))
	for _, req := range reqs {
		if serr := send4(pc, dst, req); serr != nil {
			return sent, 0, serr
		}
		wanted[req.TransactionID] = true
		sent++
	}
	deadline := time.Now().Add(drain)
	seen := make(map[dhcpv4.TransactionID]struct{}, len(reqs))
	for {
		got, ok, rerr := readUntil4(ctx, pc, func(m *dhcpv4.DHCPv4) bool { return wanted[m.TransactionID] }, deadline)
		if rerr != nil {
			return sent, len(seen), rerr
		}
		if !ok {
			return sent, len(seen), nil
		}
		seen[got.TransactionID] = struct{}{}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
