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
	"net"
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
	log.Infof("reading IPv4 leases from %s", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only open()

	records, err := parseDHCPv4Records(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return records, nil
}

// LoadDHCPv6Records loads the DHCPv6Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IPv6 address.
func LoadDHCPv6Records(filename string) (map[string]netip.Addr, error) {
	log.Infof("reading IPv6 leases from %s", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only open()

	records, err := parseDHCPv6Records(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return records, nil
}

// parseDHCPv4Records parses the MAC<->IPv4 mappings out of r. The records
// have to be one per line, a mac address and an IPv4 address.
func parseDHCPv4Records(r io.Reader) (map[string]netip.Addr, error) {
	return parseDHCPRecords(r, 4, netip.Addr.Is4)
}

// parseDHCPv6Records parses the MAC<->IPv6 mappings out of r. The records
// have to be one per line, a mac address and an IPv6 address.
func parseDHCPv6Records(r io.Reader) (map[string]netip.Addr, error) {
	return parseDHCPRecords(r, 6, netip.Addr.Is6)
}

// parseDHCPRecords parses the MAC<->IP mappings out of r. The records have to
// be one per line, a mac address and an IP address.
func parseDHCPRecords(r io.Reader, protVer int, check func(netip.Addr) bool) (map[string]netip.Addr, error) {
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
		hwaddr, err := net.ParseMAC(tokens[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: malformed hardware address: %s", lineNo, tokens[0])
		}
		ipaddr, err := netip.ParseAddr(tokens[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: expected an IPv%d address, got: %s", lineNo, protVer, tokens[1])
		}
		if !check(ipaddr) {
			return nil, fmt.Errorf("line %d: expected an IPv%d address, got: %s", lineNo, protVer, ipaddr)
		}

		// note that net.HardwareAddr.String() uses lowercase hexadecimal
		// so there's no need to convert to lowercase
		records[hwaddr.String()] = ipaddr
		addresses[strings.ToLower(tokens[0])]++
		addresses[strings.ToLower(tokens[1])]++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	duplicatesWarning(addresses)

	return records, nil
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
