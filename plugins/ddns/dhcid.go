// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"golang.org/x/net/dns/dnsmessage"
)

// ErrNoIdentity is a request with nothing in it to tell the client apart
// from any other. Without an identity there is no DHCID, and a name with no
// DHCID can be taken by anyone, so nothing is written at all.
var ErrNoIdentity = errors.New("ddns: the client sent nothing that identifies it")

const (
	// typeDHCID is the DHCID record type (RFC 4701 section 3). dnsmessage
	// has no constant for it and no body type either, so it goes on the
	// wire as opaque RDATA the way TSIG does.
	typeDHCID = dnsmessage.Type(49)

	// The identifier type codes of RFC 4701 section 3.5.
	idHTypeChaddr = 0x0000 // the htype octet and chaddr of a DHCPv4 request
	idClientID    = 0x0001 // a DHCPv4 client identifier, option 61
	idDUID        = 0x0002 // a DHCPv6 DUID, or the DUID inside an RFC 4361 option 61

	// digestSHA256 is digest type 1, which is the only digest RFC 4701
	// section 3.4 defines.
	digestSHA256 = 1

	// An RFC 4361 option 61 is a type octet of 255, a four octet IAID and
	// then the client's DUID.
	duidClientIDType = 0xff
	duidClientIDHdr  = 5

	// maxChaddr is the room BOOTP has for a hardware address. A packet that
	// claims more is trimmed rather than allowed to stretch the digest
	// input.
	maxChaddr = 16

	// htypeMask keeps the hardware type inside the one octet RFC 4701 gives
	// it.
	htypeMask = 0xff
)

// identity is what a DHCID record says about the client a name was written
// for (RFC 4701 section 3.5): a code naming which field of the request was
// taken, and the octets of that field.
//
// The same client asking for the same name produces the same DHCID and
// nothing else does, which is what holds a name against one client.
type identity struct {
	code uint16
	data []byte
}

// identity4 reads the identity out of a DHCPv4 request.
//
// Option 61 is preferred over the hardware address because a client keeps it
// across interfaces, and because RFC 4361 has a dual-stack client put the
// same DUID there as it sends over DHCPv6.
func identity4(req *dhcpv4.DHCPv4) identity {
	if raw := req.Options.Get(dhcpv4.OptionClientIdentifier); len(raw) > 0 {
		return clientID4(raw)
	}
	return identity{code: idHTypeChaddr, data: hardwareIdentity(req)}
}

// clientID4 is the identity of a client that sent option 61.
//
// RFC 4361 wraps the DUID behind a type octet of 255 and a four octet IAID.
// RFC 4701 section 3.5 wants it out of that wrapper and under code 0x0002, so
// a client holding a name over DHCPv6 is recognised over DHCPv4.
func clientID4(raw []byte) identity {
	if raw[0] == duidClientIDType && len(raw) > duidClientIDHdr {
		return identity{code: idDUID, data: raw[duidClientIDHdr:]}
	}
	return identity{code: idClientID, data: raw}
}

// hardwareIdentity is the 0x0000 form: the hardware type in one octet
// followed by the hardware address.
func hardwareIdentity(req *dhcpv4.DHCPv4) []byte {
	chaddr := req.ClientHWAddr
	if len(chaddr) > maxChaddr {
		chaddr = chaddr[:maxChaddr]
	}
	if len(chaddr) == 0 {
		return nil
	}
	out := make([]byte, 0, len(chaddr)+1)
	out = append(out, byte(uint16(req.HWType)&htypeMask))
	return append(out, chaddr...)
}

// identity6 reads the DUID out of a DHCPv6 message. RFC 8415 section 16 makes
// the client identifier mandatory, so a message without one is malformed and
// gets no record.
func identity6(msg *dhcpv6.Message) identity {
	duid := msg.Options.ClientID()
	if duid == nil {
		return identity{}
	}
	return identity{code: idDUID, data: duid.ToBytes()}
}

// record returns the DHCID RDATA that holds fqdn for this client
// (RFC 4701 section 3.5): the identifier type code, the digest type, and
// SHA-256 over the identifier followed by the name in canonical wire form.
func (id identity) record(fqdn string) ([]byte, error) {
	if len(id.data) == 0 {
		return nil, fmt.Errorf("%w, so %s is not written", ErrNoIdentity, fqdn)
	}
	wire, err := packName(fqdn)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	write(h, id.data)
	write(h, wire)
	out := make([]byte, 0, 3+sha256.Size)
	out = binary.BigEndian.AppendUint16(out, id.code)
	out = append(out, digestSHA256)
	return h.Sum(out), nil
}
