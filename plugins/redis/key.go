// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// A DUID belongs to DHCPv6 and option 61 to DHCPv4, so each non-default mode
// is refused by the other family at setup rather than missing every hash.
type keyMode uint8

const (
	keyMAC keyMode = iota
	// The whole DUID: DUID.ToBytes writes the two-octet type code first.
	keyDUID
	keyClientID
)

// RFC 8415 section 11.1 caps a DUID at 128 octets and DUID.ToBytes prepends
// the two-octet type code. Anything longer is passed on, so one packet cannot
// make the server hex encode an arbitrarily long option.
const maxDUIDLen = 130

// Indexed by keyMode, so the order has to match the constants above, and a
// slice rather than a map so the error listing the alternatives is stable.
var keyModes = []struct {
	name   string
	mode   keyMode
	prefix string
}{
	{"mac", keyMAC, defaultPrefixMAC},
	{"duid", keyDUID, defaultPrefixDUID},
	{"client-id", keyClientID, defaultPrefixClientID},
}

// Pre-boxed: these go into a log call on every request, and boxing a string
// there costs an allocation while passing an existing interface value costs
// none.
var labelArgs = [...]any{
	keyMAC:      "MAC address",
	keyDUID:     "DUID",
	keyClientID: "client identifier",
}

func parseKeyMode(raw string) (keyMode, error) {
	for _, k := range keyModes {
		if raw == k.name {
			return k.mode, nil
		}
	}
	return keyMAC, fmt.Errorf("unknown %s%s, want one of mac, duid, client-id", keyArg, raw)
}

func (m keyMode) defaultPrefix() string {
	return keyModes[m].prefix
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

// A client that sends no option 61 under key:client-id is passed on rather
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
