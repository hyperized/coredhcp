// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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

// A DUID belongs to DHCPv6 and option 61 to DHCPv4, so each non-default mode
// is refused by the other family at setup rather than matching nothing.
type keyMode uint8

const (
	keyMAC keyMode = iota
	// The whole DUID: DUID.ToBytes writes the two-octet type code first, so a
	// lease line has to carry it too.
	keyDUID
	keyClientID
)

// RFC 8415 section 11.1 caps a DUID at 128 octets and DUID.ToBytes prepends
// the two-octet type code. Refusing anything longer stops a client making the
// server hex encode an arbitrary option on every request.
const maxDUIDLen = 130

// Marks an identifier written as a string rather than as hex. Lease lines are
// split on whitespace, so the string cannot contain any.
const textPrefix = "text:"

// A slice and not a map so the error listing the alternatives comes out in
// this order every time.
var keyModes = []struct {
	name string
	mode keyMode
}{
	{"mac", keyMAC},
	{"duid", keyDUID},
	{"client-id", keyClientID},
}

func parseKeyMode(raw string) (keyMode, error) {
	for _, k := range keyModes {
		if raw == k.name {
			return k.mode, nil
		}
	}
	return keyMAC, fmt.Errorf("unknown key %q, want one of mac, duid, client-id", raw)
}

// Pre-boxed: these go into a log call on every request, and boxing a string
// there costs an allocation while passing an existing interface value costs
// none.
var labelArgs = [...]any{
	keyMAC:      "MAC address",
	keyDUID:     "DUID",
	keyClientID: "client identifier",
}

func (m keyMode) label() any {
	return labelArgs[m]
}

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

func parseMACField(field string) (string, error) {
	hwaddr, err := net.ParseMAC(field)
	if err != nil {
		return "", fmt.Errorf("malformed hardware address: %s", field)
	}
	// net.HardwareAddr.String writes lowercase hex, so no further folding.
	return hwaddr.String(), nil
}

// The type code is part of the key, as it is on the wire.
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

// RFC 2132 section 9.14 leaves option 61 open past the leading type octet, so
// an identifier is often a name: hence the text: form alongside hex.
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

// Accepts either case, an optional 0x prefix and optional colons. An empty
// value is an error: it would match no request while looking like a record.
func parseHexBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.ToLower(s), ":", "")
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, errors.New("no hexadecimal digits")
	}
	return hex.DecodeString(s)
}

// A client that sends no option 61 under key:client-id is passed on rather
// than looked up under an empty key.
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

// msg has to be the inner message, so a relayed request is keyed on the
// client's own identifier and not the relay's.
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
