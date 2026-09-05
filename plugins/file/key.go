// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Lookup keys: which client identifier a lease line is keyed on, how the
// first field of a line is canonicalised, and how the same key is derived
// from a request.

package file

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// keyMode is the client identifier a lease file is keyed on. A DUID belongs
// to DHCPv6 and option 61 to DHCPv4, so each of the two non-default modes is
// refused by the other family at setup rather than silently matching
// nothing.
type keyMode uint8

const (
	// keyMAC keys on the client's link-layer address. It is the default and
	// the only mode that works for both families.
	keyMAC keyMode = iota
	// keyDUID keys on the DHCPv6 client DUID, all of it: DUID.ToBytes writes
	// the two-octet type code first, so a lease line has to carry it too.
	keyDUID
	// keyClientID keys on the raw bytes of DHCPv4 option 61.
	keyClientID
)

// maxDUIDLen bounds the DUID a lease line may name and a request may be
// looked up by. RFC 8415 section 11.1 caps a DUID at 128 octets and
// DUID.ToBytes prepends the two-octet type code. Anything longer is not a
// DUID, and refusing it here keeps a client from making the server hex
// encode an arbitrarily long option on every request.
const maxDUIDLen = 130

// textPrefix marks a client identifier written as a string rather than as
// hex. Lease lines are split on whitespace, so the string cannot contain
// any.
const textPrefix = "text:"

// keyModes are the accepted values of the key: argument. It is a slice and
// not a map so the error listing the alternatives comes out in this order
// every time.
var keyModes = []struct {
	name string
	mode keyMode
}{
	{"mac", keyMAC},
	{"duid", keyDUID},
	{"client-id", keyClientID},
}

// parseKeyMode reads the value of a key: argument.
func parseKeyMode(raw string) (keyMode, error) {
	for _, k := range keyModes {
		if raw == k.name {
			return k.mode, nil
		}
	}
	return keyMAC, fmt.Errorf("unknown key %q, want one of mac, duid, client-id", raw)
}

// labelArgs names each identifier for the log lines the handlers write. The
// values are kept pre-boxed because they go into a log call on every request:
// converting a string to an interface value there costs one allocation, and
// passing one that is already an interface costs none.
var labelArgs = [...]any{
	keyMAC:      "MAC address",
	keyDUID:     "DUID",
	keyClientID: "client identifier",
}

// label names the identifier in log lines. It hands back an already-boxed
// value, so a handler pays nothing for it.
func (m keyMode) label() any {
	return labelArgs[m]
}

// checkFamily refuses a mode the family cannot produce.
func (m keyMode) checkFamily(v6 bool) error {
	switch {
	case m == keyDUID && !v6:
		return errors.New("key:duid works under server6 only, a DHCPv4 client has no DUID")
	case m == keyClientID && v6:
		return errors.New("key:client-id works under server4 only, DHCPv6 has no option 61")
	default:
		return nil
	}
}

// parseKeyField turns the first field of a lease line into the canonical map
// key for this mode.
func (m keyMode) parseKeyField(field string) (string, error) {
	switch m {
	case keyDUID:
		return parseDUIDField(field)
	case keyClientID:
		return parseClientIDField(field)
	default:
		return parseMACField(field)
	}
}

// parseMACField reads a link-layer address in any spelling net.ParseMAC
// accepts.
func parseMACField(field string) (string, error) {
	hwaddr, err := net.ParseMAC(field)
	if err != nil {
		return "", fmt.Errorf("malformed hardware address: %s", field)
	}
	// net.HardwareAddr.String() writes lowercase hexadecimal, so the key
	// needs no further folding.
	return hwaddr.String(), nil
}

// parseDUIDField reads the raw bytes of a DUID, type code included.
func parseDUIDField(field string) (string, error) {
	raw, err := parseHexBytes(field)
	if err != nil {
		return "", fmt.Errorf("malformed DUID: %s", field)
	}
	if len(raw) > maxDUIDLen {
		return "", fmt.Errorf("DUID is %d octets, at most %d are allowed: %s", len(raw), maxDUIDLen, field)
	}
	return hex.EncodeToString(raw), nil
}

// parseClientIDField reads option 61 either as hex or, behind text:, as the
// bytes of a string. The string form is there because a client identifier is
// often a name rather than an address; RFC 2132 section 9.14 leaves the
// content open past the leading type octet, and RFC 4361 clients put a DUID
// there under type 255.
func parseClientIDField(field string) (string, error) {
	if text, ok := strings.CutPrefix(field, textPrefix); ok {
		if text == "" {
			return "", fmt.Errorf("empty %s client identifier: %s", textPrefix, field)
		}
		return hex.EncodeToString([]byte(text)), nil
	}
	raw, err := parseHexBytes(field)
	if err != nil {
		return "", fmt.Errorf("malformed client identifier: %s", field)
	}
	return hex.EncodeToString(raw), nil
}

// parseHexBytes reads a byte string written as hexadecimal in either case,
// with an optional 0x prefix and optional colons between the bytes. An empty
// value is an error: it would match no request while looking like a record.
func parseHexBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.ToLower(s), ":", "")
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, errors.New("no hexadecimal digits")
	}
	return hex.DecodeString(s)
}

// key4 returns the lookup key for a DHCPv4 request and whether the request
// carries the identifier at all. A client that sends no option 61 under
// key:client-id is passed to the next plugin rather than looked up under an
// empty key.
func (m keyMode) key4(req *dhcpv4.DHCPv4) (string, bool) {
	if m != keyClientID {
		return req.ClientHWAddr.String(), true
	}
	raw := req.Options.Get(dhcpv4.OptionClientIdentifier)
	if len(raw) == 0 {
		log.Infof("%s sent no client identifier, passing", req.ClientHWAddr)
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// key6 returns the lookup key for a DHCPv6 request. msg has to be the inner
// message, so a relayed request is keyed on the client's own identifier and
// not on the relay's.
func (m keyMode) key6(req dhcpv6.DHCPv6, msg *dhcpv6.Message) (string, bool) {
	if m == keyDUID {
		return duidKey(msg)
	}
	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		log.Infof("Could not find client MAC for %s, passing", req)
		return "", false
	}
	return mac.String(), true
}

// duidKey hex encodes the client DUID of msg.
func duidKey(msg *dhcpv6.Message) (string, bool) {
	duid := msg.Options.ClientID()
	if duid == nil {
		log.Infof("Could not find client DUID for %s, passing", msg)
		return "", false
	}
	raw := duid.ToBytes()
	if len(raw) > maxDUIDLen {
		log.Infof("Client DUID is %d octets, more than the %d RFC 8415 allows, passing", len(raw), maxDUIDLen)
		return "", false
	}
	return hex.EncodeToString(raw), true
}
