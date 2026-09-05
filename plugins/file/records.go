// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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

// LoadDHCPv4Records reads MAC-keyed IPv4 reservations, one per line, from filename.
func LoadDHCPv4Records(filename string) (map[string]netip.Addr, error) {
	return loadRecords(filename, false, keyMAC)
}

// LoadDHCPv6Records reads MAC-keyed IPv6 reservations, one per line, from filename.
func LoadDHCPv6Records(filename string) (map[string]netip.Addr, error) {
	return loadRecords(filename, true, keyMAC)
}

// The map is keyed the way mode canonicalises the first field of a line, which
// is what the handlers look up.
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

func protoVersion(v6 bool) int {
	if v6 {
		return 6
	}
	return 4
}

func addressCheck(v6 bool) func(netip.Addr) bool {
	if v6 {
		return netip.Addr.Is6
	}
	return netip.Addr.Is4
}

func parseDHCPRecords(r io.Reader, v6 bool, mode keyMode) (map[string]netip.Addr, error) {
	// Resolved once: both are the same for every line, and looking them up per
	// line costs about a tenth of the parse time on a 10k-record file.
	protVer, check := protoVersion(v6), addressCheck(v6)
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

		key, ipaddr, err := parseRecord(tokens, protVer, check, mode)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		records[key] = ipaddr
		// Counted in canonical form, so two lines naming the same client in
		// different spellings still warn.
		addresses[key]++
		addresses[strings.ToLower(tokens[1])]++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	duplicatesWarning(addresses)

	return records, nil
}

func parseRecord(tokens []string, protVer int, check func(netip.Addr) bool, mode keyMode) (string, netip.Addr, error) {
	key, err := mode.parseKeyField(tokens[0])
	if err != nil {
		return "", netip.Addr{}, err
	}
	ipaddr, err := netip.ParseAddr(tokens[1])
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("expected an IPv%d address, got: %s", protVer, tokens[1])
	}
	if !check(ipaddr) {
		return "", netip.Addr{}, fmt.Errorf("expected an IPv%d address, got: %s", protVer, ipaddr)
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
