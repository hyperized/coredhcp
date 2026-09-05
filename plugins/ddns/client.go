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

// Failures of the exchange itself.
var (
	// ErrNoAnswer is a server that did not answer within the timeout, twice.
	ErrNoAnswer = errors.New("ddns: no answer from the DNS server")

	// ErrResponseID is an answer whose message ID is not the one that was
	// asked with. Off-path, that is a forgery; on-path, it is a stray
	// datagram from an earlier exchange.
	ErrResponseID = errors.New("ddns: response does not answer this request")

	// ErrTruncated is an answer with the TC bit set. This plugin speaks UDP
	// only, so there is nothing to retry over TCP with; see the package
	// documentation for why that is enough here.
	ErrTruncated = errors.New("ddns: response is truncated")

	// ErrRCode is an answer the server refused, carrying its reason.
	ErrRCode = errors.New("ddns: server refused the update")
)

const (
	// attempts is how many times one update is sent before it is given up
	// on. UDP loses datagrams; a second try costs one packet and covers the
	// common case, and anything beyond that is better handled by the client
	// renewing its lease.
	attempts = 2

	// maxResponse bounds a response read. An UPDATE answer is a header, an
	// echo of the zone section and a TSIG record; 4096 leaves room for a
	// server that echoes the whole request back.
	maxResponse = 4096
)

// exchange sends one signed message to the configured server and returns the
// answer.
func (p *pluginState) exchange(msg []byte) ([]byte, error) {
	//nolint:gosec // G704: the address is operator configuration, not user
	// input. applyServer has already held it to a literal IP address and a
	// port in range, and nothing out of a DHCP packet reaches it.
	conn, err := net.DialTimeout("udp", p.server, p.timeout)
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", p.server, err)
	}
	defer func() { _ = conn.Close() }()
	return p.roundTrip(conn, msg)
}

// roundTrip writes msg and reads one answer, retrying once when the read
// times out. A read that fails for any other reason is not retried: a refused
// port or a closed socket will not answer the second datagram either.
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

// checkResponse decides whether an answer says what it appears to say.
//
// The RCODE is read last on purpose. It is not covered by the MAC until the
// MAC has been checked, and a spoofed REFUSED that is believed turns into a
// DNS record that silently never appears. The message ID is checked first
// because it is the cheap filter that keeps stray datagrams out, and the
// truncation flag right after it because a truncated answer may not carry a
// TSIG record to verify at all.
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
		// A name server that is asked about a zone it does not hold has no
		// key to sign with and answers NOTAUTH unsigned, which both Knot and
		// BIND do. The code it claims is worth putting in the log, so the
		// operator sees "you pointed me at the wrong server" rather than
		// only "unsigned", but it is named as a claim: nothing in an
		// unsigned answer has been proved.
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

// rcodes names the response codes an UPDATE can come back with. dnsmessage
// only names the six that predate RFC 2136, and the ones it does not name are
// exactly the ones worth reading in a log: NOTZONE for a name outside the
// zone, NOTAUTH for a key the server does not accept for it.
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

// rcodeName names a response code for the log.
func rcodeName(code dnsmessage.RCode) string {
	if name, ok := rcodes[code]; ok {
		return name
	}
	return fmt.Sprintf("RCODE %d", code)
}
