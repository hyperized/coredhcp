// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	// ErrNoAnswer is a server that did not answer within the timeout, twice.
	ErrNoAnswer = errors.New("ddns: no answer from the DNS server")

	// ErrResponseID is an answer whose message ID does not match the request:
	// off-path, a forgery; on-path, a stray datagram from an earlier exchange.
	ErrResponseID = errors.New("ddns: response does not answer this request")

	// ErrTruncated is an answer with the TC bit set. UDP only; see the
	// package doc for why TCP retry is not needed.
	ErrTruncated = errors.New("ddns: response is truncated")

	// ErrRCode is an answer the server refused, carrying its reason.
	ErrRCode = errors.New("ddns: server refused the update")
)

const (
	// One retry covers the common lost-datagram case; further loss is
	// better handled by the client renewing its lease.
	attempts = 2

	// Room for a server that echoes the whole request back in its answer.
	maxResponse = 4096
)

func (p *pluginState) exchange(msg []byte) ([]byte, error) {
	//nolint:gosec // G704: address is operator config, already validated as a literal IP:port.
	conn, err := net.DialTimeout("udp", p.server, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", p.server, err)
	}
	defer func() { _ = conn.Close() }()
	return p.roundTrip(conn, msg)
}

// Retries only on read timeout: a refused port or closed socket will not
// answer a second datagram either.
func (p *pluginState) roundTrip(conn net.Conn, msg []byte) ([]byte, error) {
	buf := make([]byte, maxResponse)
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			return nil, fmt.Errorf("setting the deadline: %w", err)
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, fmt.Errorf("sending to %s: %w", p.server, err)
		}
		n, err := conn.Read(buf)
		if err == nil {
			return buf[:n], nil
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, fmt.Errorf("reading from %s: %w", p.server, err)
		}
		log.Debugf("%s did not answer within %s, attempt %d of %d", p.server, p.timeout, attempt, attempts)
	}
	return nil, fmt.Errorf("%w %s after %d attempts", ErrNoAnswer, p.server, attempts)
}

// RCODE is checked only after the MAC verifies: a spoofed REFUSED accepted
// before that would silently drop a record that was never actually rejected.
func (p *pluginState) checkResponse(resp, requestMAC []byte, requestID uint16) error {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(resp)
	if err != nil {
		return fmt.Errorf("parsing the response: %w", err)
	}
	if hdr.ID != requestID {
		return fmt.Errorf("%w: asked with id %d, answered with %d", ErrResponseID, requestID, hdr.ID)
	}
	if hdr.Truncated {
		return ErrTruncated
	}
	rec, err := findTSIG(resp)
	if err != nil {
		// Knot and BIND both answer NOTAUTH unsigned for a zone they don't hold;
		// the claimed code is logged but not trusted, since it is unsigned.
		return fmt.Errorf("%w (it claims %s, which is not proof of anything)", err, rcodeName(hdr.RCode))
	}
	if err := p.key.verify(resp, rec, requestMAC); err != nil {
		return err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("%w: %s", ErrRCode, rcodeName(hdr.RCode))
	}
	return nil
}

// dnsmessage only names the six RCODEs that predate RFC 2136; NOTAUTH and
// NOTZONE below fill in the ones an UPDATE actually needs for its log lines.
var rcodes = map[dnsmessage.RCode]string{
	0:  "NOERROR",
	1:  "FORMERR",
	2:  "SERVFAIL",
	3:  "NXDOMAIN",
	4:  "NOTIMP",
	5:  "REFUSED",
	6:  "YXDOMAIN",
	7:  "YXRRSET",
	8:  "NXRRSET",
	9:  "NOTAUTH",
	10: "NOTZONE",
}

func rcodeName(code dnsmessage.RCode) string {
	if name, ok := rcodes[code]; ok {
		return name
	}
	return fmt.Sprintf("RCODE %d", code)
}
