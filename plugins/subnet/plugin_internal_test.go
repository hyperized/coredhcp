// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package subnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "subnets.yml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// -----------------------------------------------------------------------
// config.go
// -----------------------------------------------------------------------

func TestParseFile(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := parseFile(filepath.Join(t.TempDir(), "missing.yml"))
		require.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		path := writeYAML(t, "")
		_, err := parseFile(path)
		require.ErrorIs(t, err, errNoSubnets)
	})

	t.Run("malformed YAML", func(t *testing.T) {
		// A leading tab is invalid YAML indentation, so this never reaches
		// the strict-decoding step at all.
		path := writeYAML(t, "\tsubnets: []\n")
		_, err := parseFile(path)
		require.Error(t, err)
	})

	t.Run("unknown field", func(t *testing.T) {
		path := writeYAML(t, "subnets: [{name: a, cidr: 10.0.0.0/24, default: true, bogus: 1}]\n")
		_, err := parseFile(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bogus")
	})

	t.Run("compile error propagates", func(t *testing.T) {
		path := writeYAML(t, "subnets:\n  - cidr: 10.0.0.0/24\n    default: true\n")
		_, err := parseFile(path)
		require.ErrorIs(t, err, errNoName)
	})

	t.Run("success", func(t *testing.T) {
		path := writeYAML(t, "subnets:\n  - name: a\n    cidr: 10.0.0.0/24\n    default: true\n")
		scopes, err := parseFile(path)
		require.NoError(t, err)
		assert.Len(t, scopes, 1)
	})
}

func TestCompile(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		_, err := compile(nil)
		require.ErrorIs(t, err, errNoSubnets)
	})

	t.Run("parseSubnet error", func(t *testing.T) {
		_, err := compile([]subnetConfig{{CIDR: "10.0.0.0/24", Default: true}})
		require.ErrorIs(t, err, errNoName)
	})

	t.Run("checkFile error", func(t *testing.T) {
		list := []subnetConfig{
			{Name: "a", CIDR: "10.0.0.0/24", Default: true},
			{Name: "a", CIDR: "10.0.1.0/24", Default: true},
		}
		_, err := compile(list)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate name")
	})

	t.Run("success", func(t *testing.T) {
		list := []subnetConfig{{Name: "a", CIDR: "10.0.0.0/24", Default: true}}
		scopes, err := compile(list)
		require.NoError(t, err)
		assert.Len(t, scopes, 1)
	})
}

func TestSubnetError(t *testing.T) {
	err := subnetError(0, "", errNoName)
	assert.EqualError(t, err, `subnet #1: every subnet needs a name`)

	err = subnetError(2, "office", errNoLease)
	assert.EqualError(t, err, `subnet "office": a subnet that hands out addresses needs a lease`)
}

func TestParseSubnet(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		_, err := parseSubnet(subnetConfig{CIDR: "10.0.0.0/24", Default: true})
		require.ErrorIs(t, err, errNoName)
	})

	t.Run("unparseable cidr", func(t *testing.T) {
		_, err := parseSubnet(subnetConfig{Name: "a", CIDR: "not-a-cidr", Default: true})
		require.Error(t, err)
	})

	t.Run("error from one of the five steps", func(t *testing.T) {
		// No match rule and not default: parseMatch is the failing step.
		_, err := parseSubnet(subnetConfig{Name: "a", CIDR: "10.0.0.0/24"})
		require.ErrorIs(t, err, errNoMatchRule)
	})

	t.Run("success", func(t *testing.T) {
		sc, err := parseSubnet(subnetConfig{Name: "a", CIDR: "10.0.0.0/24", Default: true})
		require.NoError(t, err)
		assert.Equal(t, "a", sc.sub.name)
		assert.True(t, sc.v4)
	})
}

func TestParseMatch(t *testing.T) {
	t.Run("empty interface name", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{}}
		err := parseMatch(s, &subnetConfig{Match: matchConfig{Interfaces: []string{""}}})
		require.ErrorIs(t, err, errEmptyInterface)
	})

	t.Run("bad relay entry", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{}}
		err := parseMatch(s, &subnetConfig{Match: matchConfig{Relays: []string{"not-an-ip"}}})
		require.Error(t, err)
	})

	t.Run("no interfaces, no relays, not default", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{}}
		err := parseMatch(s, &subnetConfig{})
		require.ErrorIs(t, err, errNoMatchRule)
	})

	t.Run("success", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{}}
		err := parseMatch(s, &subnetConfig{Match: matchConfig{
			Interfaces: []string{"eth0"},
			Relays:     []string{"10.0.0.1"},
		}})
		require.NoError(t, err)
		assert.Equal(t, []string{"eth0"}, s.sub.ifaces)
		assert.Len(t, s.sub.relays, 1)
	})
}

func TestParseRelay(t *testing.T) {
	t.Run("prefix form does not parse", func(t *testing.T) {
		_, err := parseRelay("10.0.0.0/40", true)
		require.Error(t, err)
	})

	t.Run("prefix form wrong family", func(t *testing.T) {
		_, err := parseRelay("2001:db8::/32", true)
		require.Error(t, err)
	})

	t.Run("prefix form ok", func(t *testing.T) {
		p, err := parseRelay("10.0.9.0/24", true)
		require.NoError(t, err)
		assert.Equal(t, 24, p.Bits())
	})

	t.Run("bare address does not parse", func(t *testing.T) {
		_, err := parseRelay("not-an-ip", true)
		require.Error(t, err)
	})

	t.Run("bare address ok, becomes a host prefix", func(t *testing.T) {
		p4, err := parseRelay("10.0.0.1", true)
		require.NoError(t, err)
		assert.Equal(t, 32, p4.Bits())

		p6, err := parseRelay("2001:db8::1", false)
		require.NoError(t, err)
		assert.Equal(t, 128, p6.Bits())
	})
}

func TestParseLease(t *testing.T) {
	t.Run("absent while a pool exists", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Pool: "10.0.0.10-10.0.0.20"})
		require.ErrorIs(t, err, errNoLease)
	})

	t.Run("absent while a prefixpool exists", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{PrefixPool: "2001:db8::/48"})
		require.ErrorIs(t, err, errNoLease)
	})

	t.Run("absent while reservations exist", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Reservations: map[string]string{"aa:bb:cc:dd:ee:ff": "10.0.0.1"}})
		require.ErrorIs(t, err, errNoLease)
	})

	t.Run("absent with none of those is fine", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{})
		require.NoError(t, err)
	})

	t.Run("unparseable", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Lease: "forever"})
		require.Error(t, err)
	})

	t.Run("zero", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Lease: "0s"})
		require.Error(t, err)
	})

	t.Run("negative", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Lease: "-1h"})
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseLease(s, &subnetConfig{Lease: "1h"})
		require.NoError(t, err)
		assert.Equal(t, time.Hour, s.lease)
		assert.Equal(t, time.Hour, s.sub.lease)
	})
}

func TestParsePool4(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	t.Run("prefixpool set on an IPv4 subnet", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{PrefixPool: "2001:db8::/48"})
		require.ErrorIs(t, err, errPrefixOnV4)
	})

	t.Run("prefixsize set on an IPv4 subnet", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{PrefixSize: 64})
		require.ErrorIs(t, err, errPrefixOnV4)
	})

	t.Run("no pool but a leasedb", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{LeaseDB: "x.sqlite3"})
		require.ErrorIs(t, err, errDBWithoutPool)
	})

	t.Run("neither is fine", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{})
		require.NoError(t, err)
	})

	t.Run("pool without leasedb", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{Pool: "10.0.0.10-10.0.0.20"})
		require.ErrorIs(t, err, errPoolWithoutDB)
	})

	t.Run("parseRange error", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{Pool: "not-a-range", LeaseDB: "x.sqlite3"})
		require.Error(t, err)
	})

	t.Run("pool start outside the cidr", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{Pool: "10.0.1.10-10.0.1.20", LeaseDB: "x.sqlite3"})
		require.Error(t, err)
	})

	t.Run("pool start inside but end outside the cidr", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{Pool: "10.0.0.10-10.0.1.20", LeaseDB: "x.sqlite3"})
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parsePool4(s, &subnetConfig{Pool: "10.0.0.10-10.0.0.20", LeaseDB: "x.sqlite3"})
		require.NoError(t, err)
		require.NotNil(t, s.pool)
		assert.Equal(t, "x.sqlite3", s.leasedb)
	})
}

func TestParseRange(t *testing.T) {
	t.Run("no dash", func(t *testing.T) {
		_, err := parseRange("10.0.0.10")
		require.Error(t, err)
	})

	t.Run("unparseable start", func(t *testing.T) {
		_, err := parseRange("bad-10.0.0.20")
		require.Error(t, err)
	})

	t.Run("unparseable end", func(t *testing.T) {
		_, err := parseRange("10.0.0.10-bad")
		require.Error(t, err)
	})

	t.Run("start above end", func(t *testing.T) {
		_, err := parseRange("10.0.0.20-10.0.0.10")
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		r, err := parseRange("10.0.0.10-10.0.0.20")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.10", r.start.String())
		assert.Equal(t, "10.0.0.20", r.end.String())
	})

	t.Run("surrounding whitespace is trimmed", func(t *testing.T) {
		r, err := parseRange("10.0.0.10 - 10.0.0.20")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.10", r.start.String())
		assert.Equal(t, "10.0.0.20", r.end.String())
	})
}

func TestParsePool6(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/48")

	t.Run("pool set on an IPv6 subnet", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{Pool: "10.0.0.10-10.0.0.20"})
		require.ErrorIs(t, err, errPoolOnV6)
	})

	t.Run("leasedb set on an IPv6 subnet", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{LeaseDB: "x.sqlite3"})
		require.ErrorIs(t, err, errPoolOnV6)
	})

	t.Run("prefixsize without a prefixpool", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixSize: 64})
		require.ErrorIs(t, err, errSizeWithoutPool)
	})

	t.Run("neither is fine", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{})
		require.NoError(t, err)
	})

	t.Run("unparseable prefixpool", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixPool: "not-a-cidr", PrefixSize: 64})
		require.Error(t, err)
	})

	t.Run("an IPv4 prefixpool on an IPv6 subnet", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixPool: "10.0.0.0/24", PrefixSize: 64})
		require.Error(t, err)
	})

	t.Run("prefixsize below the prefixpool length", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixPool: "2001:db8::/48", PrefixSize: 32})
		require.Error(t, err)
	})

	t.Run("prefixsize above 128", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixPool: "2001:db8::/48", PrefixSize: 129})
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: cidr}}
		err := parsePool6(s, &subnetConfig{PrefixPool: "2001:db8::/48", PrefixSize: 64})
		require.NoError(t, err)
		assert.Equal(t, 64, s.prefixSize)
		assert.True(t, s.prefixPool.IsValid())
	})
}

func TestParseReservations(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	t.Run("none is fine", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{})
		require.NoError(t, err)
	})

	t.Run("reservations on an IPv6 subnet", func(t *testing.T) {
		s := &scope{v4: false, sub: &subnet{cidr: netip.MustParsePrefix("2001:db8::/48")}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{"aa:bb:cc:dd:ee:ff": "2001:db8::1"},
		})
		require.ErrorIs(t, err, errReservationsV6)
	})

	t.Run("unparseable MAC", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{"not-a-mac": "10.0.0.5"},
		})
		require.Error(t, err)
	})

	t.Run("the same MAC twice in two notations", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{
				"aa:bb:cc:dd:ee:01": "10.0.0.5",
				"aa-bb-cc-dd-ee-01": "10.0.0.6",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate")
	})

	t.Run("unparseable address", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{"aa:bb:cc:dd:ee:ff": "not-an-ip"},
		})
		require.Error(t, err)
	})

	t.Run("address outside the cidr", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{"aa:bb:cc:dd:ee:ff": "10.0.1.5"},
		})
		require.Error(t, err)
	})

	t.Run("success, keyed by canonical MAC form", func(t *testing.T) {
		s := &scope{v4: true, sub: &subnet{cidr: cidr}}
		err := parseReservations(s, &subnetConfig{
			Reservations: map[string]string{"AA:BB:CC:DD:EE:01": "10.0.0.5"},
		})
		require.NoError(t, err)
		ip, ok := s.sub.reservations["aa:bb:cc:dd:ee:01"]
		require.True(t, ok)
		assert.Equal(t, "10.0.0.5", ip.String())
	})
}

func TestParseOptions4(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	t.Run("unparseable router", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{Router: "not-an-ip"})
		require.Error(t, err)
	})

	t.Run("router outside the cidr", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{Router: "10.0.1.1"})
		require.Error(t, err)
	})

	t.Run("bad dns entry", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{DNS: []string{"not-an-ip"}})
		require.Error(t, err)
	})

	t.Run("bad ntp entry", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{NTP: []string{"not-an-ip"}})
		require.Error(t, err)
	})

	t.Run("every option set", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{
			Router: "10.0.0.1",
			DNS:    []string{"10.0.0.53"},
			Domain: "example.test",
			NTP:    []string{"10.0.0.123"},
		})
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", s.sub.opts4.router.String())
		assert.Equal(t, "example.test", s.sub.opts4.domain)
		assert.Len(t, s.sub.opts4.dns, 1)
		assert.Len(t, s.sub.opts4.ntp, 1)
	})

	t.Run("no options set", func(t *testing.T) {
		s := &scope{sub: &subnet{cidr: cidr}}
		err := parseOptions4(s, &optionsConfig{})
		require.NoError(t, err)
		assert.Nil(t, s.sub.opts4.router)
		assert.Empty(t, s.sub.opts4.domain)
		assert.Nil(t, s.sub.opts4.dns)
		assert.Nil(t, s.sub.opts4.ntp)
		assert.Equal(t, net.CIDRMask(24, 32), s.sub.opts4.mask)
	})
}

func TestParseOptions6(t *testing.T) {
	t.Run("router set", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseOptions6(s, &optionsConfig{Router: "2001:db8::1"})
		require.ErrorIs(t, err, errOptionsV4Only)
	})

	t.Run("domain set", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseOptions6(s, &optionsConfig{Domain: "example.test"})
		require.ErrorIs(t, err, errOptionsV4Only)
	})

	t.Run("ntp set", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseOptions6(s, &optionsConfig{NTP: []string{"2001:db8::123"}})
		require.ErrorIs(t, err, errOptionsV4Only)
	})

	t.Run("bad dns entry", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseOptions6(s, &optionsConfig{DNS: []string{"not-an-ip"}})
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		s := &scope{sub: &subnet{}}
		err := parseOptions6(s, &optionsConfig{DNS: []string{"2001:db8::53"}})
		require.NoError(t, err)
		assert.Len(t, s.sub.dns6, 1)
	})
}

func TestCheckNames(t *testing.T) {
	scopes := []*scope{
		{sub: &subnet{name: "a"}},
		{sub: &subnet{name: "a"}},
	}
	err := checkNames(scopes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate name")
}

func TestCheckDefaults(t *testing.T) {
	t.Run("two defaults in the same family", func(t *testing.T) {
		scopes := []*scope{
			{v4: true, sub: &subnet{name: "a", isDefault: true}},
			{v4: true, sub: &subnet{name: "b", isDefault: true}},
		}
		err := checkDefaults(scopes)
		require.Error(t, err)
	})

	t.Run("one default per family passes", func(t *testing.T) {
		scopes := []*scope{
			{v4: true, sub: &subnet{name: "a", isDefault: true}},
			{v4: false, sub: &subnet{name: "b", isDefault: true}},
		}
		err := checkDefaults(scopes)
		require.NoError(t, err)
	})
}

func TestCheckLeaseDBs(t *testing.T) {
	scopes := []*scope{
		{sub: &subnet{name: "a"}, leasedb: "x.sqlite3"},
		{sub: &subnet{name: "b"}, leasedb: "x.sqlite3"},
	}
	err := checkLeaseDBs(scopes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x.sqlite3")
}

func TestCheckPools(t *testing.T) {
	t.Run("overlapping IPv4 pools", func(t *testing.T) {
		r1 := addrRange{start: netip.MustParseAddr("10.0.0.10"), end: netip.MustParseAddr("10.0.0.20")}
		r2 := addrRange{start: netip.MustParseAddr("10.0.0.15"), end: netip.MustParseAddr("10.0.0.25")}
		scopes := []*scope{
			{sub: &subnet{name: "a"}, pool: &r1},
			{sub: &subnet{name: "b"}, pool: &r2},
		}
		err := checkPools(scopes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlaps")
	})

	t.Run("overlapping prefixpools", func(t *testing.T) {
		scopes := []*scope{
			{sub: &subnet{name: "a"}, prefixPool: netip.MustParsePrefix("2001:db8::/48")},
			{sub: &subnet{name: "b"}, prefixPool: netip.MustParsePrefix("2001:db8::/56")},
		}
		err := checkPools(scopes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlaps")
	})

	t.Run("adjacent but not overlapping pools pass", func(t *testing.T) {
		r1 := addrRange{start: netip.MustParseAddr("10.0.0.10"), end: netip.MustParseAddr("10.0.0.20")}
		r2 := addrRange{start: netip.MustParseAddr("10.0.0.21"), end: netip.MustParseAddr("10.0.0.30")}
		scopes := []*scope{
			{sub: &subnet{name: "a"}, pool: &r1},
			{sub: &subnet{name: "b"}, pool: &r2},
		}
		err := checkPools(scopes)
		require.NoError(t, err)
	})
}

func TestAddrRangeStringAndOverlaps(t *testing.T) {
	r := addrRange{start: netip.MustParseAddr("10.0.0.10"), end: netip.MustParseAddr("10.0.0.20")}
	assert.Equal(t, "10.0.0.10-10.0.0.20", r.String())

	shared := addrRange{start: netip.MustParseAddr("10.0.0.20"), end: netip.MustParseAddr("10.0.0.30")}
	assert.True(t, r.overlaps(shared), "sharing an endpoint counts as overlap")

	disjoint := addrRange{start: netip.MustParseAddr("10.0.0.21"), end: netip.MustParseAddr("10.0.0.30")}
	assert.False(t, r.overlaps(disjoint))
}

func TestParsePrefix(t *testing.T) {
	t.Run("unparseable", func(t *testing.T) {
		_, err := parsePrefix("not-a-cidr", "cidr")
		require.Error(t, err)
	})

	t.Run("IPv4-mapped form is rejected", func(t *testing.T) {
		_, err := parsePrefix("::ffff:10.0.0.0/120", "cidr")
		require.ErrorIs(t, err, errMappedPrefix)
	})

	t.Run("success, returned masked", func(t *testing.T) {
		p, err := parsePrefix("10.0.0.5/24", "cidr")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.0/24", p.String())
	})
}

func TestParseIP(t *testing.T) {
	t.Run("unparseable", func(t *testing.T) {
		_, err := parseIP("not-an-ip", true, "router")
		require.Error(t, err)
	})

	t.Run("wrong family", func(t *testing.T) {
		_, err := parseIP("2001:db8::1", true, "router")
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		a, err := parseIP("10.0.0.1", true, "router")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", a.String())
	})
}

func TestParseIPs(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		out, err := parseIPs(nil, true, "dns")
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("error", func(t *testing.T) {
		_, err := parseIPs([]string{"not-an-ip"}, true, "dns")
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		out, err := parseIPs([]string{"10.0.0.53", "10.0.0.54"}, true, "dns")
		require.NoError(t, err)
		assert.Len(t, out, 2)
	})
}

func TestFamilyName(t *testing.T) {
	assert.Equal(t, "IPv4", familyName(true))
	assert.Equal(t, "IPv6", familyName(false))
}

// -----------------------------------------------------------------------
// plugin.go
// -----------------------------------------------------------------------

func TestFilePath(t *testing.T) {
	t.Run("zero arguments", func(t *testing.T) {
		_, err := filePath(nil)
		require.Error(t, err)
	})

	t.Run("two arguments", func(t *testing.T) {
		_, err := filePath([]string{"file:a", "file:b"})
		require.Error(t, err)
	})

	t.Run("argument without the file: prefix", func(t *testing.T) {
		_, err := filePath([]string{"a.yml"})
		require.Error(t, err)
	})

	t.Run("exactly file: with an empty path", func(t *testing.T) {
		_, err := filePath([]string{"file:"})
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		path, err := filePath([]string{"file:/etc/coredhcp/subnets.yml"})
		require.NoError(t, err)
		assert.Equal(t, "/etc/coredhcp/subnets.yml", path)
	})
}

func TestNewSelector4(t *testing.T) {
	t.Run("filePath error", func(t *testing.T) {
		_, err := newSelector4()
		require.Error(t, err)
	})

	t.Run("parseFile error", func(t *testing.T) {
		_, err := newSelector4("file:" + filepath.Join(t.TempDir(), "missing.yml"))
		require.Error(t, err)
	})

	t.Run("only the other family configured", func(t *testing.T) {
		path := writeYAML(t, "subnets:\n  - name: v6\n    cidr: 2001:db8::/48\n    default: true\n")
		_, err := newSelector4("file:" + path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no IPv4 subnets configured")
	})

	t.Run("buildDelegate error names the subnet", func(t *testing.T) {
		leasedb := filepath.Join(t.TempDir(), "no-such-dir", "leases.sqlite3")
		body := fmt.Sprintf("subnets:\n"+
			"  - name: broken\n"+
			"    cidr: 10.0.0.0/24\n"+
			"    default: true\n"+
			"    pool: 10.0.0.100-10.0.0.200\n"+
			"    lease: 1h\n"+
			"    leasedb: %s\n", leasedb)
		path := writeYAML(t, body)
		_, err := newSelector4("file:" + path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"broken"`)
	})

	t.Run("default subnet recorded, success", func(t *testing.T) {
		leasedb := filepath.Join(t.TempDir(), "leases.sqlite3")
		body := fmt.Sprintf("subnets:\n"+
			"  - name: main\n"+
			"    cidr: 10.0.0.0/24\n"+
			"    default: true\n"+
			"    pool: 10.0.0.100-10.0.0.200\n"+
			"    lease: 1h\n"+
			"    leasedb: %s\n", leasedb)
		path := writeYAML(t, body)
		s, err := newSelector4("file:" + path)
		require.NoError(t, err)
		require.NotNil(t, s.def)
		assert.Equal(t, "main", s.def.name)
		assert.Len(t, s.subnets, 1)
	})
}

func TestNewSelector6(t *testing.T) {
	t.Run("filePath error", func(t *testing.T) {
		_, err := newSelector6()
		require.Error(t, err)
	})

	t.Run("parseFile error", func(t *testing.T) {
		_, err := newSelector6("file:" + filepath.Join(t.TempDir(), "missing.yml"))
		require.Error(t, err)
	})

	t.Run("only the other family configured", func(t *testing.T) {
		path := writeYAML(t, "subnets:\n  - name: v4\n    cidr: 10.0.0.0/24\n    default: true\n")
		_, err := newSelector6("file:" + path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no IPv6 subnets configured")
	})

	t.Run("buildDelegate error names the subnet", func(t *testing.T) {
		body := "subnets:\n" +
			"  - name: huge\n" +
			"    cidr: 2001:db8::/48\n" +
			"    default: true\n" +
			"    prefixpool: 2001:db8::/48\n" +
			"    prefixsize: 128\n" +
			"    lease: 1h\n"
		path := writeYAML(t, body)
		_, err := newSelector6("file:" + path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"huge"`)
	})

	t.Run("default subnet recorded, success", func(t *testing.T) {
		body := "subnets:\n" +
			"  - name: main\n" +
			"    cidr: 2001:db8::/48\n" +
			"    match:\n" +
			"      interfaces: [eth0]\n" +
			"    default: true\n" +
			"    prefixpool: 2001:db8::/48\n" +
			"    prefixsize: 64\n" +
			"    lease: 1h\n"
		path := writeYAML(t, body)
		s, err := newSelector6("file:" + path)
		require.NoError(t, err)
		require.NotNil(t, s.def)
		assert.Equal(t, "main", s.def.name)
	})
}

func TestBuildDelegateNoPool(t *testing.T) {
	sc := &scope{sub: &subnet{name: "x"}}
	err := buildDelegate(sc)
	require.NoError(t, err)
	assert.Nil(t, sc.sub.handler4)
	assert.Nil(t, sc.sub.handler6)
}

func TestSelectorHandle4(t *testing.T) {
	t.Run("no subnet matches, passes through unchanged", func(t *testing.T) {
		s := &selector{}
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		require.NoError(t, err)
		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		got, stop := s.handle4(context.Background(), req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
	})

	t.Run("delegates to the matched subnet", func(t *testing.T) {
		sub := &subnet{
			name:      "main",
			cidr:      netip.MustParsePrefix("10.0.0.0/24"),
			isDefault: true,
			opts4:     options4{mask: net.CIDRMask(24, 32)},
		}
		s := &selector{subnets: []*subnet{sub}, def: sub}
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		require.NoError(t, err)
		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		got, stop := s.handle4(context.Background(), req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
		assert.NotNil(t, got.Options.Get(dhcpv4.OptionSubnetMask))
	})
}

func TestSelectorHandle6(t *testing.T) {
	t.Run("no subnet matches, passes through unchanged", func(t *testing.T) {
		s := &selector{}
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		got, stop := s.handle6(context.Background(), req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
	})

	t.Run("delegates to the matched subnet", func(t *testing.T) {
		sub := &subnet{
			name:      "main",
			cidr:      netip.MustParsePrefix("2001:db8::/48"),
			isDefault: true,
			dns6:      []net.IP{net.ParseIP("2001:db8::53")},
		}
		s := &selector{subnets: []*subnet{sub}, def: sub}
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		got, stop := s.handle6(context.Background(), req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
		assert.NotNil(t, got.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
	})
}

func TestSelectorSelect4(t *testing.T) {
	office := &subnet{
		name:   "office",
		cidr:   netip.MustParsePrefix("10.0.1.0/24"),
		relays: []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
	}
	guest := &subnet{
		name:   "guest",
		cidr:   netip.MustParsePrefix("10.0.2.0/24"),
		ifaces: []string{"eth2"},
	}
	fallback := &subnet{name: "fallback", cidr: netip.MustParsePrefix("10.0.3.0/24"), isDefault: true}
	s := &selector{subnets: []*subnet{office, guest, fallback}, def: fallback}

	newReq := func(t *testing.T) *dhcpv4.DHCPv4 {
		t.Helper()
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		require.NoError(t, err)
		return req
	}

	cases := []struct {
		name string
		req  func(t *testing.T) *dhcpv4.DHCPv4
		ctx  context.Context
		want *subnet
	}{
		{
			name: "giaddr matches an entry in match.relays",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.GatewayIPAddr = net.ParseIP("10.0.1.1")
				return req
			},
			ctx:  context.Background(),
			want: office,
		},
		{
			name: "giaddr matches a subnet's cidr that lists no relays",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.GatewayIPAddr = net.ParseIP("10.0.2.50")
				return req
			},
			ctx:  context.Background(),
			want: guest,
		},
		{
			name: "giaddr set but matches nothing, falls through to ciaddr then default",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.GatewayIPAddr = net.ParseIP("192.168.0.1")
				req.ClientIPAddr = net.ParseIP("10.0.2.60")
				return req
			},
			ctx:  context.Background(),
			want: guest,
		},
		{
			name: "giaddr unset, context interface matches",
			req:  newReq,
			ctx:  handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth2"}),
			want: guest,
		},
		{
			name: "giaddr unset, no interface match, falls through to default",
			req:  newReq,
			ctx:  handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth9"}),
			want: fallback,
		},
		{
			name: "ciaddr renewal",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.ClientIPAddr = net.ParseIP("10.0.1.50")
				return req
			},
			ctx:  context.Background(),
			want: office,
		},
		{
			name: "option 50 requested address when ciaddr is unset",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.2.70")))
				return req
			},
			ctx:  context.Background(),
			want: guest,
		},
		{
			name: "missing RequestInfo falls through to the cidr and default rules",
			req: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req := newReq(t)
				req.ClientIPAddr = net.ParseIP("10.0.1.80")
				return req
			},
			ctx:  context.Background(),
			want: office,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req(t)
			got := s.select4(tc.ctx, req)
			assert.Same(t, tc.want, got)
		})
	}
}

func TestSelectorSelect4NothingMatchesNoDefault(t *testing.T) {
	s := &selector{subnets: []*subnet{
		{name: "only", cidr: netip.MustParsePrefix("10.0.9.0/24"), ifaces: []string{"eth9"}},
	}}
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	require.NoError(t, err)
	assert.Nil(t, s.select4(context.Background(), req))
}

func TestSelectorSelect6(t *testing.T) {
	relayed1 := &subnet{
		name:   "relayed1",
		cidr:   netip.MustParsePrefix("2001:db8:1::/48"),
		relays: []netip.Prefix{netip.MustParsePrefix("2001:db8:9::1/128")},
	}
	relayed2 := &subnet{name: "relayed2", cidr: netip.MustParsePrefix("2001:db8:2::/48")}
	direct := &subnet{name: "direct", cidr: netip.MustParsePrefix("2001:db8:3::/48"), ifaces: []string{"eth3"}}
	fallback := &subnet{name: "fallback", cidr: netip.MustParsePrefix("2001:db8:4::/48"), isDefault: true}
	s := &selector{subnets: []*subnet{relayed1, relayed2, direct, fallback}, def: fallback}

	relayedReq := func(t *testing.T, linkAddr string) dhcpv6.DHCPv6 {
		t.Helper()
		inner, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		relayed, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP(linkAddr), net.ParseIP("fe80::1"))
		require.NoError(t, err)
		return relayed
	}

	directReq := func(t *testing.T) dhcpv6.DHCPv6 {
		t.Helper()
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		return req
	}

	cases := []struct {
		name string
		req  dhcpv6.DHCPv6
		ctx  context.Context
		want *subnet
	}{
		{"relayed, link-address in match.relays", relayedReq(t, "2001:db8:9::1"), context.Background(), relayed1},
		{"relayed, link-address inside a relay-less subnet's cidr", relayedReq(t, "2001:db8:2::50"), context.Background(), relayed2},
		{
			// Deliberate design decision: a relayed request that matches
			// nothing goes straight to the default, never to the interface
			// rule, even though the context names a matching interface.
			"relayed matching nothing falls to default, not to the interface rule",
			relayedReq(t, "2001:db8:ffff::1"),
			handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth3"}),
			fallback,
		},
		{"relayed with an unspecified link address", relayedReq(t, "::"), context.Background(), fallback},
		{
			"direct, interface matches",
			directReq(t),
			handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth3"}),
			direct,
		},
		{
			"direct, no match, falls to default",
			directReq(t),
			handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth9"}),
			fallback,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.select6(tc.ctx, tc.req)
			assert.Same(t, tc.want, got)
		})
	}
}

func TestSelectorSelect6NothingMatchesNoDefault(t *testing.T) {
	s := &selector{subnets: []*subnet{
		{name: "only", cidr: netip.MustParsePrefix("2001:db8::/48"), ifaces: []string{"eth0"}},
	}}
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	assert.Nil(t, s.select6(context.Background(), req))
}

func TestByInterfaceEmptyName(t *testing.T) {
	// An empty name means "no interface information", so it must never match
	// even a subnet that (invalidly) lists an empty one.
	s := &selector{subnets: []*subnet{{name: "a", ifaces: []string{""}}}}
	assert.Nil(t, s.byInterface(""))
}

func TestByAddress(t *testing.T) {
	s := &selector{subnets: []*subnet{{name: "a", cidr: netip.MustParsePrefix("10.0.0.0/24")}}}

	t.Run("invalid address", func(t *testing.T) {
		assert.Nil(t, s.byAddress(netip.Addr{}))
	})

	t.Run("valid address matching nothing", func(t *testing.T) {
		assert.Nil(t, s.byAddress(netip.MustParseAddr("10.0.1.5")))
	})
}

func TestClaimsRelay(t *testing.T) {
	t.Run("no relays, matches via cidr", func(t *testing.T) {
		sub := &subnet{cidr: netip.MustParsePrefix("10.0.0.0/24")}
		assert.True(t, sub.claimsRelay(netip.MustParseAddr("10.0.0.1")))
		assert.False(t, sub.claimsRelay(netip.MustParseAddr("10.0.1.1")))
	})

	t.Run("relays configured", func(t *testing.T) {
		sub := &subnet{
			cidr:   netip.MustParsePrefix("10.0.0.0/24"),
			relays: []netip.Prefix{netip.MustParsePrefix("192.168.0.1/32")},
		}
		assert.True(t, sub.claimsRelay(netip.MustParseAddr("192.168.0.1")))
		// An address inside the subnet's own cidr no longer counts once
		// relays are explicitly configured.
		assert.False(t, sub.claimsRelay(netip.MustParseAddr("10.0.0.1")))
	})
}

func TestSubnetHandle4(t *testing.T) {
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	newReq := func(t *testing.T, mt dhcpv4.MessageType) *dhcpv4.DHCPv4 {
		t.Helper()
		req, err := dhcpv4.New(dhcpv4.WithMessageType(mt))
		require.NoError(t, err)
		req.ClientHWAddr = mac
		return req
	}

	newResp := func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
		t.Helper()
		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("RELEASE goes straight to the delegate without options being set", func(t *testing.T) {
		var delegateCalled bool
		sub := &subnet{
			opts4: options4{router: net.ParseIP("10.0.0.1")},
			handler4: func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				delegateCalled = true
				return resp, false
			},
		}
		req := newReq(t, dhcpv4.MessageTypeRelease)
		resp := newResp(t, req)
		got, stop := sub.handle4(req, resp)
		assert.True(t, delegateCalled)
		assert.Same(t, resp, got)
		assert.False(t, stop)
		assert.Nil(t, got.Options.Get(dhcpv4.OptionRouter))
	})

	t.Run("DECLINE goes straight to the delegate without options being set", func(t *testing.T) {
		var delegateCalled bool
		sub := &subnet{
			opts4: options4{router: net.ParseIP("10.0.0.1")},
			handler4: func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				delegateCalled = true
				return resp, false
			},
		}
		req := newReq(t, dhcpv4.MessageTypeDecline)
		resp := newResp(t, req)
		got, _ := sub.handle4(req, resp)
		assert.True(t, delegateCalled)
		assert.Nil(t, got.Options.Get(dhcpv4.OptionRouter))
	})

	t.Run("INFORM gets the options and returns (resp, false)", func(t *testing.T) {
		sub := &subnet{opts4: options4{mask: net.CIDRMask(24, 32), router: net.ParseIP("10.0.0.1")}}
		req := newReq(t, dhcpv4.MessageTypeInform)
		resp := newResp(t, req)
		got, stop := sub.handle4(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
		assert.NotNil(t, got.Options.Get(dhcpv4.OptionRouter))
	})

	t.Run("reserved MAC gets YourIPAddr and option 51, and the reservation is cloned", func(t *testing.T) {
		sub := &subnet{
			opts4:        options4{mask: net.CIDRMask(24, 32)},
			lease:        time.Hour,
			reservations: map[string]net.IP{mac.String(): net.ParseIP("10.0.0.5").To4()},
		}

		req1 := newReq(t, dhcpv4.MessageTypeRequest)
		resp1 := newResp(t, req1)
		got1, stop := sub.handle4(req1, resp1)
		require.True(t, stop)
		require.Equal(t, "10.0.0.5", got1.YourIPAddr.String())
		assert.NotNil(t, got1.Options.Get(dhcpv4.OptionIPAddressLeaseTime))

		// Mutating the first response's address must not leak into the
		// reservation table and affect a later request.
		got1.YourIPAddr[0] = 0xff

		req2 := newReq(t, dhcpv4.MessageTypeRequest)
		resp2 := newResp(t, req2)
		got2, _ := sub.handle4(req2, resp2)
		assert.Equal(t, "10.0.0.5", got2.YourIPAddr.String())
	})

	t.Run("unreserved MAC goes to the delegate", func(t *testing.T) {
		var delegateCalled bool
		sub := &subnet{
			opts4: options4{mask: net.CIDRMask(24, 32)},
			handler4: func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
				delegateCalled = true
				return resp, true
			},
		}
		req := newReq(t, dhcpv4.MessageTypeRequest)
		resp := newResp(t, req)
		_, stop := sub.handle4(req, resp)
		assert.True(t, delegateCalled)
		assert.True(t, stop)
	})

	t.Run("no pool passes through with (resp, false)", func(t *testing.T) {
		sub := &subnet{opts4: options4{mask: net.CIDRMask(24, 32)}}
		req := newReq(t, dhcpv4.MessageTypeRequest)
		resp := newResp(t, req)
		got, stop := sub.handle4(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
	})
}

func TestOptions4Apply(t *testing.T) {
	newResp := func(t *testing.T) *dhcpv4.DHCPv4 {
		t.Helper()
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		require.NoError(t, err)
		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("mask is always set, the rest absent when not configured", func(t *testing.T) {
		o := options4{mask: net.CIDRMask(24, 32)}
		resp := newResp(t)
		o.apply(resp)
		assert.NotNil(t, resp.Options.Get(dhcpv4.OptionSubnetMask))
		assert.Nil(t, resp.Options.Get(dhcpv4.OptionRouter))
		assert.Nil(t, resp.Options.Get(dhcpv4.OptionDomainNameServer))
		assert.Nil(t, resp.Options.Get(dhcpv4.OptionDomainName))
		assert.Nil(t, resp.Options.Get(dhcpv4.OptionNTPServers))
	})

	t.Run("router, dns, domain and ntp set when configured", func(t *testing.T) {
		o := options4{
			mask:   net.CIDRMask(24, 32),
			router: net.ParseIP("10.0.0.1"),
			dns:    []net.IP{net.ParseIP("10.0.0.53")},
			domain: "example.test",
			ntp:    []net.IP{net.ParseIP("10.0.0.123")},
		}
		resp := newResp(t)
		o.apply(resp)
		assert.NotNil(t, resp.Options.Get(dhcpv4.OptionRouter))
		assert.NotNil(t, resp.Options.Get(dhcpv4.OptionDomainNameServer))
		assert.NotNil(t, resp.Options.Get(dhcpv4.OptionDomainName))
		assert.NotNil(t, resp.Options.Get(dhcpv4.OptionNTPServers))
	})
}

func TestSubnetHandle6(t *testing.T) {
	newExchange := func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
		t.Helper()
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		return req, resp
	}

	t.Run("dns set", func(t *testing.T) {
		sub := &subnet{dns6: []net.IP{net.ParseIP("2001:db8::53")}}
		req, resp := newExchange(t)
		got, stop := sub.handle6(req, resp)
		assert.False(t, stop)
		assert.NotNil(t, got.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
	})

	t.Run("dns unset", func(t *testing.T) {
		sub := &subnet{}
		req, resp := newExchange(t)
		got, stop := sub.handle6(req, resp)
		assert.False(t, stop)
		assert.Nil(t, got.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
	})

	t.Run("delegate present", func(t *testing.T) {
		var called bool
		sub := &subnet{handler6: func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			called = true
			return resp, true
		}}
		req, resp := newExchange(t)
		_, stop := sub.handle6(req, resp)
		assert.True(t, called)
		assert.True(t, stop)
	})

	t.Run("delegate absent", func(t *testing.T) {
		sub := &subnet{}
		req, resp := newExchange(t)
		got, stop := sub.handle6(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
	})
}

func TestInterfaceFrom(t *testing.T) {
	t.Run("with RequestInfo", func(t *testing.T) {
		ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth1"})
		assert.Equal(t, "eth1", interfaceFrom(ctx))
	})

	t.Run("without RequestInfo", func(t *testing.T) {
		assert.Empty(t, interfaceFrom(context.Background()))
	})
}

func TestClientAddr4(t *testing.T) {
	newReq := func(t *testing.T) *dhcpv4.DHCPv4 {
		t.Helper()
		req, err := dhcpv4.New()
		require.NoError(t, err)
		return req
	}

	t.Run("with ciaddr", func(t *testing.T) {
		req := newReq(t)
		req.ClientIPAddr = net.ParseIP("10.0.0.5")
		assert.Equal(t, "10.0.0.5", clientAddr4(req).String())
	})

	t.Run("with only option 50", func(t *testing.T) {
		req := newReq(t)
		req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.0.9")))
		assert.Equal(t, "10.0.0.9", clientAddr4(req).String())
	})

	t.Run("with neither", func(t *testing.T) {
		req := newReq(t)
		assert.False(t, clientAddr4(req).IsValid())
	})
}

func TestAddrFrom(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, ok := addrFrom(nil)
		assert.False(t, ok)
	})

	t.Run("unspecified IPv4", func(t *testing.T) {
		_, ok := addrFrom(net.IPv4zero)
		assert.False(t, ok)
	})

	t.Run("unspecified IPv6", func(t *testing.T) {
		_, ok := addrFrom(net.IPv6unspecified)
		assert.False(t, ok)
	})

	t.Run("valid IPv4", func(t *testing.T) {
		addr, ok := addrFrom(net.ParseIP("10.0.0.5").To4())
		require.True(t, ok)
		assert.True(t, addr.Is4())
		assert.Equal(t, "10.0.0.5", addr.String())
	})

	t.Run("valid IPv6", func(t *testing.T) {
		addr, ok := addrFrom(net.ParseIP("2001:db8::1"))
		require.True(t, ok)
		assert.True(t, addr.Is6())
		assert.Equal(t, "2001:db8::1", addr.String())
	})

	t.Run("IPv4-mapped IPv6 comes back unmapped as IPv4", func(t *testing.T) {
		// net.ParseIP always stores an IPv4 address in its 16-byte form, so
		// this is the mapped form addrFrom has to recognise and unwrap.
		addr, ok := addrFrom(net.ParseIP("10.0.0.5"))
		require.True(t, ok)
		assert.True(t, addr.Is4())
		assert.Equal(t, "10.0.0.5", addr.String())
	})
}
