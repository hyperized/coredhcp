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

// Logged at debug, not error: a rejected name only costs the client its
// record, and DHCP segments send oddly-named devices constantly.
var (
	// ErrNoHostname is a client that sent no name at all, or an empty one.
	ErrNoHostname = errors.New("ddns: no hostname")

	// ErrInvalidHostname is a name that fails the RFC 1035 section 2.3.1 label syntax.
	ErrInvalidHostname = errors.New("ddns: invalid hostname")

	// ErrOutsideZone is a fully qualified name outside the configured zone:
	// writing it would touch a zone this server has no key for.
	ErrOutsideZone = errors.New("ddns: name is outside the zone")

	// ErrBadName is a name that cannot be put on the wire, or one read off
	// the wire that is malformed.
	ErrBadName = errors.New("ddns: malformed DNS name")

	// ErrReverseBoundary is a reverse prefix that does not end on a label
	// boundary of its arpa tree.
	ErrReverseBoundary = errors.New("ddns: reverse prefix does not end on a zone boundary")
)

const (
	// maxLabel and maxName are the RFC 1035 section 2.3.4 size limits, in octets.
	maxLabel = 63
	maxName  = 253

	// Both carry a trailing dot: every name this package passes around is
	// fully qualified.
	arpaV4 = "in-addr.arpa."
	arpaV6 = "ip6.arpa."

	hexDigits = "0123456789abcdef"
)

// The zone apex is not under itself: a client claiming the zone name is
// refused the same as one claiming a different zone.
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

func canonicalZone(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err := validName(name); err != nil {
		return "", fmt.Errorf("invalid zone %q: %w", raw, err)
	}
	return name + ".", nil
}

// name must already be lowercase with no trailing dot.
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

// label must already be lowercase.
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

// Narrower than what DNS allows: these names come from packets anyone on the
// segment can send, so anything but an unambiguous host name is refused.
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

// Labels are ordered least-significant first, matching arpa zone convention.
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

func ptrName(addr netip.Addr) string {
	labels, suffix := arpaLabels(addr)
	return joinName(labels, suffix)
}

func reverseZone(pfx netip.Prefix) (string, error) {
	units, err := reverseUnits(pfx)
	if err != nil {
		return "", err
	}
	labels, suffix := arpaLabels(pfx.Masked().Addr())
	return joinName(labels[len(labels)-units:], suffix), nil
}

// A prefix that doesn't end on a label boundary has no zone of its own; it
// would need an RFC 2317 delegation whose name this plugin cannot guess.
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

func joinName(labels []string, suffix string) string {
	if len(labels) == 0 {
		return suffix
	}
	return strings.Join(labels, ".") + "." + suffix
}

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
		//nolint:gosec // length already bounded by maxLabel (63) above.
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// Compression pointers are refused: RFC 8945 section 4.2 forbids them in TSIG
// RDATA, and a bare DHCP option has no message to point into anyway.
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

func orRoot(name string) string {
	if name == "" {
		return "."
	}
	return name
}
