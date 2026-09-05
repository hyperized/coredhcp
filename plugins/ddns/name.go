// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Names a client asked for that this plugin refuses to write. They are all
// reported at debug level: a name that does not pass costs the client its DNS
// record and nothing else, and a network with a handful of appliances whose
// names carry underscores would otherwise fill the log.
var (
	// ErrNoHostname is a client that sent no name at all, or an empty one.
	ErrNoHostname = errors.New("ddns: no hostname")

	// ErrInvalidHostname is a name that is not a plain DNS name: an empty
	// label, one over 63 octets, a leading or trailing hyphen, or a
	// character outside [a-z0-9-].
	ErrInvalidHostname = errors.New("ddns: invalid hostname")

	// ErrOutsideZone is a fully qualified name that does not sit under the
	// configured zone. Writing it would mean updating a zone this server was
	// never given a key for, so the name is dropped rather than rewritten
	// into the zone we do hold.
	ErrOutsideZone = errors.New("ddns: name is outside the zone")

	// ErrBadName is a name that cannot be put on the wire, or one read off
	// the wire that is malformed.
	ErrBadName = errors.New("ddns: malformed DNS name")

	// ErrReverseBoundary is a reverse: prefix that does not end on a label
	// boundary of its .arpa tree.
	ErrReverseBoundary = errors.New("ddns: reverse prefix does not end on a zone boundary")
)

const (
	// maxLabel and maxName are the DNS limits, in octets, on one label and
	// on a name in presentation form without its trailing dot.
	maxLabel = 63
	maxName  = 253

	// The two reverse trees. Both carry a trailing dot: every name this
	// package passes around is fully qualified.
	arpaV4 = "in-addr.arpa."
	arpaV6 = "ip6.arpa."

	hexDigits = "0123456789abcdef"
)

// hostFQDN turns the name a client asked for into the fully qualified name to
// write, with a trailing dot. zone carries a trailing dot too.
//
// A single label is relative and is appended to the zone. Anything with a dot
// in it has to already be the fully qualified form of a name under the zone.
// The zone apex is not under itself, so a client that claims the zone name is
// refused along with one that claims someone else's zone: both are either a
// misconfiguration or an attempt to have the server write where it should not.
func hostFQDN(raw, zone string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" {
		return "", ErrNoHostname
	}
	if !strings.Contains(name, ".") {
		name += "." + strings.TrimSuffix(zone, ".")
	}
	if err := validName(name); err != nil {
		return "", err
	}
	fqdn := name + "."
	if !strings.HasSuffix(fqdn, "."+zone) {
		return "", fmt.Errorf("%w: %s is not under %s", ErrOutsideZone, fqdn, zone)
	}
	return fqdn, nil
}

// canonicalZone lowercases a configured zone and gives it a trailing dot.
func canonicalZone(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err := validName(name); err != nil {
		return "", fmt.Errorf("invalid zone %q: %w", raw, err)
	}
	return name + ".", nil
}

// validName checks a lowercase name that carries no trailing dot.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: the name is empty", ErrInvalidHostname)
	}
	if len(name) > maxName {
		return fmt.Errorf("%w: %q is %d octets, the limit is %d", ErrInvalidHostname, name, len(name), maxName)
	}
	for _, label := range strings.Split(name, ".") {
		if err := validLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// validLabel checks one lowercase label.
func validLabel(label string) error {
	if label == "" || len(label) > maxLabel {
		return fmt.Errorf("%w: label %q has to be 1 to %d octets", ErrInvalidHostname, label, maxLabel)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrInvalidHostname, label)
	}
	if !onlyNameBytes(label) {
		return fmt.Errorf("%w: label %q has a character outside [a-z0-9-]", ErrInvalidHostname, label)
	}
	return nil
}

// onlyNameBytes reports whether label is made of the characters a host name
// is allowed to use here. The set is deliberately narrower than what DNS
// permits: these names go into a zone from packets anyone on the segment can
// send, so anything that is not an unambiguous host name is refused.
func onlyNameBytes(label string) bool {
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// arpaLabels returns the labels of addr's reverse name, least significant
// first, and the tree they sit in. For 10.0.0.5 that is ["5","0","0","10"]
// under in-addr.arpa.; for an IPv6 address it is the 32 nibbles in the same
// order under ip6.arpa.
func arpaLabels(addr netip.Addr) ([]string, string) {
	if addr.Is4() {
		b := addr.As4()
		labels := make([]string, len(b))
		for i, o := range b {
			labels[len(b)-1-i] = strconv.Itoa(int(o))
		}
		return labels, arpaV4
	}
	b := addr.As16()
	labels := make([]string, 2*len(b))
	for i, o := range b {
		labels[2*len(b)-1-2*i] = string(hexDigits[o>>4])
		labels[2*len(b)-2-2*i] = string(hexDigits[o&0xf])
	}
	return labels, arpaV6
}

// ptrName returns the PTR owner name for addr, with a trailing dot.
func ptrName(addr netip.Addr) string {
	labels, suffix := arpaLabels(addr)
	return joinName(labels, suffix)
}

// reverseZone returns the reverse zone that covers pfx.
func reverseZone(pfx netip.Prefix) (string, error) {
	units, err := reverseUnits(pfx)
	if err != nil {
		return "", err
	}
	labels, suffix := arpaLabels(pfx.Masked().Addr())
	return joinName(labels[len(labels)-units:], suffix), nil
}

// reverseUnits returns how many reverse labels pfx's prefix length names.
//
// A reverse zone cuts on a label boundary: one octet in in-addr.arpa. and one
// nibble in ip6.arpa. A prefix that ends anywhere else has no zone of its own
// and is served by an RFC 2317 style delegation whose name this plugin cannot
// guess, so it is refused at setup instead of being quietly rounded to
// something that would send updates to the wrong server.
func reverseUnits(pfx netip.Prefix) (int, error) {
	per := 4
	unit := "4"
	if pfx.Addr().Is4() {
		per, unit = 8, "8"
	}
	if pfx.Bits()%per != 0 {
		return 0, fmt.Errorf("%w: %s, the prefix length has to be a multiple of %s", ErrReverseBoundary, pfx, unit)
	}
	return pfx.Bits() / per, nil
}

// joinName joins labels and the tree they sit in into a fully qualified name.
func joinName(labels []string, suffix string) string {
	if len(labels) == 0 {
		return suffix
	}
	return strings.Join(labels, ".") + "." + suffix
}

// packName returns the uncompressed, lowercase wire form of a fully qualified
// name. The root by itself is ".".
func packName(name string) ([]byte, error) {
	if !strings.HasSuffix(name, ".") {
		return nil, fmt.Errorf("%w: %q has no trailing dot", ErrBadName, name)
	}
	body := strings.ToLower(name[:len(name)-1])
	out := make([]byte, 0, len(name)+1)
	if body == "" {
		return append(out, 0), nil
	}
	for _, label := range strings.Split(body, ".") {
		if label == "" || len(label) > maxLabel {
			return nil, fmt.Errorf("%w: label %q in %q has to be 1 to %d octets", ErrBadName, label, name, maxLabel)
		}
		//nolint:gosec // The length is checked against maxLabel, which is 63,
		// on the line above.
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// readName reads one uncompressed name from the front of b and returns it in
// presentation form, lowercased and with a trailing dot, together with the
// number of octets it consumed.
//
// Compression pointers are refused. Both callers read a name out of a
// standalone byte string rather than out of a message -- a TSIG RDATA, where
// RFC 8945 section 4.2 forbids compression, and a DHCP option, which has no
// message to point into -- so a pointer there is malformed either way.
func readName(b []byte) (string, int, error) {
	var out strings.Builder
	for off := 0; off < len(b); {
		length := int(b[off])
		if length == 0 {
			return orRoot(out.String()), off + 1, nil
		}
		if length > maxLabel {
			return "", 0, fmt.Errorf("%w: label length %d, compression is not allowed here", ErrBadName, length)
		}
		off++
		if off+length > len(b) {
			return "", 0, fmt.Errorf("%w: label runs past the end of the buffer", ErrBadName)
		}
		out.WriteString(strings.ToLower(string(b[off : off+length])))
		out.WriteByte('.')
		off += length
	}
	return "", 0, fmt.Errorf("%w: the name is not terminated", ErrBadName)
}

// orRoot names the empty name, which is the DNS root.
func orRoot(name string) string {
	if name == "" {
		return "."
	}
	return name
}
