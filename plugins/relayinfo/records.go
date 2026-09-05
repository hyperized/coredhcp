// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Mapping-file parsing: the plain-text record format shared by the DHCPv4 and
// DHCPv6 variants, and the loader that reads it from disk.

package relayinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	// hexPrefix marks a key written as raw bytes rather than as text.
	hexPrefix = "0x"

	// defaultLease is the lease time and the DHCPv6 lifetimes used for a
	// mapping whose line does not give one. An hour is short enough that a
	// re-provisioned port is picked up the same day, and long enough not to
	// make every port renew constantly.
	defaultLease = time.Hour

	// leaseResolution is the granularity of a lease on the wire: DHCPv4
	// option 51 and the DHCPv6 lifetimes are both a whole number of seconds.
	leaseResolution = time.Second
)

// record is one mapping: the address handed to whoever shows up on that port,
// and the lease time or lifetimes it comes with.
type record struct {
	addr  netip.Addr
	lease time.Duration
}

// loadRecords reads the mapping file at filename. v6 selects which address
// family the file has to contain.
func loadRecords(filename string, v6 bool) (map[string]record, error) {
	family := familyOf(v6)
	log.Infof("reading %s relay mappings from %s", family, filename)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only open()

	records, err := parseRecords(f, v6)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return records, nil
}

// parseRecords parses the key -> address mappings out of r, one per line.
func parseRecords(r io.Reader, v6 bool) (map[string]record, error) {
	records := make(map[string]record)
	keyCounts := make(map[string]int)
	addrCounts := make(map[string]int)

	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}
		key, rec, err := parseRecord(line, v6)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		records[string(key)] = rec
		keyCounts[keyText(string(key))]++
		addrCounts[rec.addr.String()]++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	duplicatesWarning("Key", keyCounts)
	duplicatesWarning("Address", addrCounts)
	return records, nil
}

// parseRecord parses one non-empty, comment-free line.
func parseRecord(line string, v6 bool) ([]byte, record, error) {
	tokens := strings.Fields(line)
	if len(tokens) < 2 || len(tokens) > 3 {
		return nil, record{}, fmt.Errorf("malformed line, want `<key> <ip> [lease]`, got %d fields: %s",
			len(tokens), line)
	}

	key, err := parseKey(tokens[0])
	if err != nil {
		return nil, record{}, err
	}
	addr, err := parseAddr(tokens[1], v6)
	if err != nil {
		return nil, record{}, err
	}
	lease := defaultLease
	if len(tokens) == 3 {
		if lease, err = parseLease(tokens[2]); err != nil {
			return nil, record{}, err
		}
	}
	return key, record{addr: addr, lease: lease}, nil
}

// parseKey turns one key token into the bytes it has to match on the wire,
// either as text or as 0x-prefixed hex. The hex form is case-insensitive in
// both the prefix and the digits, so that a key starting with "0X" is never
// mistaken for text.
func parseKey(token string) ([]byte, error) {
	var key []byte
	if hasHexPrefix(token) {
		digits := token[len(hexPrefix):]
		if digits == "" {
			return nil, fmt.Errorf("empty hex key: %s", token)
		}
		decoded, err := hex.DecodeString(digits)
		if err != nil {
			return nil, fmt.Errorf("malformed hex key %s: %w", token, err)
		}
		key = decoded
	} else {
		if i := strings.IndexFunc(token, func(r rune) bool { return r < '!' || r > '~' }); i >= 0 {
			return nil, fmt.Errorf("key is neither printable ASCII nor %s-prefixed hex: %q", hexPrefix, token)
		}
		key = []byte(token)
	}

	if len(key) > maxKeyLen {
		return nil, fmt.Errorf("key is %d bytes, over the %d byte limit: %s", len(key), maxKeyLen, token)
	}
	return key, nil
}

// hasHexPrefix reports whether token is written in the hex form.
func hasHexPrefix(token string) bool {
	return len(token) >= len(hexPrefix) && strings.EqualFold(token[:len(hexPrefix)], hexPrefix)
}

// parseAddr parses the address of a mapping and rejects one from the wrong
// family, which would otherwise only fail once a client showed up on that
// port.
func parseAddr(token string, v6 bool) (netip.Addr, error) {
	family := familyOf(v6)
	addr, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("expected an %s address, got: %s", family, token)
	}
	// Is4 is false for a v4-mapped v6 address, which is what a server6
	// section wants: an IA_NA carries sixteen bytes either way.
	if addr.Is4() == v6 {
		return netip.Addr{}, fmt.Errorf("expected an %s address, got: %s", family, addr)
	}
	return addr, nil
}

// parseLease parses the optional per-line lease time.
func parseLease(token string) (time.Duration, error) {
	lease, err := time.ParseDuration(token)
	if err != nil {
		return 0, fmt.Errorf("malformed lease duration: %s", token)
	}
	if lease < leaseResolution {
		return 0, fmt.Errorf("lease duration must be at least %s, got: %s", leaseResolution, token)
	}
	return lease.Round(leaseResolution), nil
}

// familyOf names a protocol family for error messages and log lines.
func familyOf(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

// stripComment drops a trailing comment and the whitespace around a line.
func stripComment(line string) string {
	if i := strings.IndexRune(line, '#'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// keyText renders a key value the way the mapping file would have to spell
// it: as text when every byte is printable ASCII, and as hex otherwise. Log
// lines go through it so that a binary circuit-id can be pasted straight into
// the file.
func keyText(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] < '!' || key[i] > '~' {
			return hexPrefix + hex.EncodeToString([]byte(key))
		}
	}
	return key
}

// duplicatesWarning logs whatever appears in the file more than once. It is
// not an error: the last line wins, and an operator moving a subscriber
// between ports may well have two lines in flight.
func duplicatesWarning(what string, counts map[string]int) {
	var duplicates []string
	for value, count := range counts {
		if count > 1 {
			duplicates = append(duplicates, fmt.Sprintf("%s %s is in %d records", what, value, count))
		}
	}

	slices.Sort(duplicates)
	for _, warning := range duplicates {
		log.Warning(warning)
	}
}
