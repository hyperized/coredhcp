// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// problems collects every mismatch in one reply, so a failing scenario says
// what was wrong with the whole packet instead of the first field that did
// not match.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// equal records a mismatch when got and want differ as text. Rendering both
// sides is deliberate: an option is compared against what the configuration
// spelled, and the spelling is what an operator would grep for.
func (p *problems) equal(what, got, want string) {
	if got != want {
		p.addf("%s is %q, the configuration says %q", what, got, want)
	}
}

func (p *problems) truth(what string, ok bool, why string) {
	if !ok {
		p.addf("%s: %s", what, why)
	}
}

// err turns the collected mismatches into one error, or nil when there were
// none.
func (p *problems) err() error {
	if len(*p) == 0 {
		return nil
	}
	return errors.New(strings.Join(*p, "; "))
}

// join returns the error of the first argument that has one, so a scenario
// can stop at a transport failure and still report assertion failures the
// same way.
func join(errs ...error) error {
	return errors.Join(errs...)
}

// ipsToString renders a list of addresses the way the configuration writes
// one: space separated, in order.
func ipsToString(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = normalizeIP(ip)
	}
	return strings.Join(parts, " ")
}

// normalizeIP renders an address the way netip does, so a v4-mapped v6
// address and its dotted-quad form compare equal.
func normalizeIP(ip net.IP) string {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ip.String()
	}
	return a.Unmap().String()
}

// toAddr converts a net.IP to a netip.Addr, unmapping v4 so comparisons with
// a parsed configuration value work.
func toAddr(ip net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// argsToString joins configuration arguments back into the line they came
// from, for comparing against a rendered option list.
func argsToString(args []string) string {
	return strings.Join(args, " ")
}
