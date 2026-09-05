// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Lookup keys: which client identifier the hash keys are built from, and how
// that identifier is read out of a request.

package redis

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// keyMode is the client identifier the Redis keys are built from. A DUID
// belongs to DHCPv6 and option 61 to DHCPv4, so each of the two non-default
// modes is refused by the other family at setup rather than quietly missing
// every hash.
type keyMode uint8

const (
	// keyMAC builds the key from the client's link-layer address. It is the
	// default and the only mode both families accept.
	keyMAC keyMode = iota
	// keyDUID builds the key from the DHCPv6 client DUID, all of it:
	// DUID.ToBytes writes the two-octet type code first.
	keyDUID
	// keyClientID builds the key from the raw bytes of DHCPv4 option 61.
	keyClientID
)

// maxDUIDLen bounds the DUID a request may be looked up by. RFC 8415 section
// 11.1 caps a DUID at 128 octets and DUID.ToBytes prepends the two-octet
// type code. A client sending more than that is passed on instead, so one
// packet cannot make the server hex encode an arbitrarily long option.
const maxDUIDLen = 130

// keyModes are the accepted values of the key: argument, together with the
// key prefix each one defaults to. It is indexed by keyMode, so its order has
// to match the constants above, and it is a slice rather than a map so the
// error listing the alternatives comes out in this order every time.
var keyModes = []struct {
	name   string
	mode   keyMode
	prefix string
}{
	{"mac", keyMAC, defaultPrefixMAC},
	{"duid", keyDUID, defaultPrefixDUID},
	{"client-id", keyClientID, defaultPrefixClientID},
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

// parseKeyMode reads the value of the key: argument.
func parseKeyMode(raw string) (keyMode, error) {
	for _, k := range keyModes {
		if raw == k.name {
			return k.mode, nil
		}
	}
	return keyMAC, fmt.Errorf("unknown %s%s, want one of mac, duid, client-id", keyArg, raw)
}

// defaultPrefix is the key prefix this mode uses when the config line gives
// no prefix: of its own.
func (m keyMode) defaultPrefix() string {
	return keyModes[m].prefix
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

// key4 returns the identifier part of the Redis key for a DHCPv4 request,
// and whether the request carries that identifier at all. A client that
// sends no option 61 under key:client-id is passed to the next plugin rather
// than looked up under the bare prefix.
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

// key6 returns the identifier part of the Redis key for a DHCPv6 request.
// msg has to be the inner message, so a relayed request is keyed on the
// client's own identifier and not on the relay's.
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

// duidKey hex encodes the client DUID of msg, lowercase and without
// separators.
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
