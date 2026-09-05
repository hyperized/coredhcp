// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Lease-file parsing: the plain-text record format shared by the DHCPv4 and
// DHCPv6 variants, and the exported loaders that read it from disk.

package file

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"unicode"
)

// LoadDHCPv4Records loads the DHCPv4Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IPv4 address.
func LoadDHCPv4Records(filename string) (map[string]netip.Addr, error) {
	return loadRecords(filename, false, keyMAC)
}

// LoadDHCPv6Records loads the DHCPv6Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IPv6 address.
func LoadDHCPv6Records(filename string) (map[string]netip.Addr, error) {
	return loadRecords(filename, true, keyMAC)
}

// loadRecords reads filename for the given family and key mode. The map it
// returns is keyed the way mode canonicalises the first field of a line,
// which is what the handlers look up.
func loadRecords(filename string, v6 bool, mode keyMode) (map[string]netip.Addr, error) {
	log.Infof("reading IPv%d leases from %s", protoVersion(v6), filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only open()

	records, err := parseDHCPRecords(f, v6, mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return records, nil
}

// protoVersion is the IP version of a family, for the messages that name it.
func protoVersion(v6 bool) int {
	if v6 {
		return 6
	}
	return 4
}

// addressCheck returns the test an address has to pass to belong to the
// family being loaded.
func addressCheck(v6 bool) func(netip.Addr) bool {
	if v6 {
		return netip.Addr.Is6
	}
	return netip.Addr.Is4
}

// parseDHCPRecords parses the identifier<->IP mappings out of r. The records
// have to be one per line, an identifier of the kind mode names followed by
// an IP address of the family v6 names.
func parseDHCPRecords(r io.Reader, v6 bool, mode keyMode) (map[string]netip.Addr, error) {
	addresses := make(map[string]int)
	records := make(map[string]netip.Addr)
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNo++
		if comment := strings.IndexRune(line, '#'); comment >= 0 {
			line = strings.TrimRightFunc(line[:comment], unicode.IsSpace)
		}
		if len(line) == 0 {
			continue
		}

		tokens := strings.Fields(line)
		if len(tokens) != 2 {
			return nil, fmt.Errorf("line %d: malformed line, want 2 fields, got %d: %s", lineNo, len(tokens), line)
		}

		key, ipaddr, err := parseRecord(tokens, v6, mode)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		records[key] = ipaddr
		// The identifier is counted in canonical form, so two lines naming
		// the same client in different spellings still warn. The address is
		// counted as written, which costs nothing on a file that is already
		// lowercase.
		addresses[key]++
		addresses[strings.ToLower(tokens[1])]++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	duplicatesWarning(addresses)

	return records, nil
}

// parseRecord turns the two fields of one lease line into the canonical
// lookup key of the first and the address of the second.
func parseRecord(tokens []string, v6 bool, mode keyMode) (string, netip.Addr, error) {
	key, err := mode.parseKeyField(tokens[0])
	if err != nil {
		return "", netip.Addr{}, err
	}
	ipaddr, err := netip.ParseAddr(tokens[1])
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("expected an IPv%d address, got: %s", protoVersion(v6), tokens[1])
	}
	if !addressCheck(v6)(ipaddr) {
		return "", netip.Addr{}, fmt.Errorf("expected an IPv%d address, got: %s", protoVersion(v6), ipaddr)
	}
	return key, ipaddr, nil
}

func duplicatesWarning(ipAddresses map[string]int) {
	var duplicates []string
	for ipAddress, count := range ipAddresses {
		if count > 1 {
			duplicates = append(duplicates, fmt.Sprintf("Address %s is in %d records", ipAddress, count))
		}
	}

	sort.Strings(duplicates)

	for _, warning := range duplicates {
		log.Warning(warning)
	}
}
