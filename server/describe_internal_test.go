// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"

	"github.com/coredhcp/coredhcp/events"
)

func TestReply6GetInnerMessageError(t *testing.T) {
	r := &requestReport{}
	// A relay with no inner message option: GetInnerMessage fails, so the
	// method must return without touching r.ev.
	r.reply6(&dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward})
	assert.Empty(t, r.ev.ReplyType)
	assert.Empty(t, r.ev.Addresses)
}

func TestReply6IANAAndIAPDTogetherReportShortestLease(t *testing.T) {
	msg := mustMessage6(t, dhcpv6.MessageTypeReply)
	msg.AddOption(&dhcpv6.OptIANA{
		IaId: [4]byte{1, 2, 3, 4},
		Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          net.ParseIP("2001:db8::10"),
				PreferredLifetime: time.Hour,
				ValidLifetime:     2 * time.Hour,
			},
		}},
	})
	msg.AddOption(&dhcpv6.OptIAPD{
		IaId: [4]byte{5, 6, 7, 8},
		Options: dhcpv6.PDOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAPrefix{
				Prefix:        &net.IPNet{IP: net.ParseIP("2001:db8:1::"), Mask: net.CIDRMask(56, 128)},
				ValidLifetime: time.Hour,
			},
		}},
	})

	r := &requestReport{}
	r.reply6(msg)

	assert.Equal(t, "REPLY", r.ev.ReplyType)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("2001:db8::10/128"),
		netip.MustParsePrefix("2001:db8:1::/56"),
	}, r.ev.Addresses)
	// The IA_PD's one-hour lifetime is shorter than the IA_NA's two hours.
	assert.Equal(t, time.Hour, r.ev.LeaseTime)
}

func TestReply6IATALoop(t *testing.T) {
	msg := mustMessage6(t, dhcpv6.MessageTypeReply)
	msg.AddOption(&dhcpv6.OptIATA{
		IaId: [4]byte{9, 9, 9, 9},
		Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAAddress{
				IPv6Addr:      net.ParseIP("2001:db8::20"),
				ValidLifetime: 30 * time.Minute,
			},
		}},
	})

	r := &requestReport{}
	r.reply6(msg)

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::20/128")}, r.ev.Addresses)
	assert.Equal(t, 30*time.Minute, r.ev.LeaseTime)
}

func TestAddAddresses6InvalidAddressSkipped(t *testing.T) {
	tests := []struct {
		name string
		addr net.IP
	}{
		{name: "nil address", addr: nil},
		{name: "unspecified address", addr: net.IPv6unspecified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &requestReport{}
			r.addAddresses6([]*dhcpv6.OptIAAddress{{IPv6Addr: tc.addr, ValidLifetime: time.Hour}})
			assert.Empty(t, r.ev.Addresses)
			assert.Zero(t, r.ev.LeaseTime)
		})
	}
}

func TestAddPrefixes6(t *testing.T) {
	tests := []struct {
		name      string
		prefixes  []*dhcpv6.OptIAPrefix
		wantAddrs []netip.Prefix
		wantLease time.Duration
	}{
		{
			name: "delegated prefix added at its own length",
			prefixes: []*dhcpv6.OptIAPrefix{{
				Prefix:        &net.IPNet{IP: net.ParseIP("2001:db8:2::"), Mask: net.CIDRMask(48, 128)},
				ValidLifetime: 45 * time.Minute,
			}},
			wantAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/48")},
			wantLease: 45 * time.Minute,
		},
		{
			name: "nil Prefix is skipped",
			prefixes: []*dhcpv6.OptIAPrefix{{
				Prefix:        nil,
				ValidLifetime: time.Hour,
			}},
		},
		{
			name: "invalid prefix address is skipped",
			prefixes: []*dhcpv6.OptIAPrefix{{
				Prefix:        &net.IPNet{IP: net.IPv6unspecified, Mask: net.CIDRMask(56, 128)},
				ValidLifetime: time.Hour,
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &requestReport{}
			r.addPrefixes6(tc.prefixes)
			assert.Equal(t, tc.wantAddrs, r.ev.Addresses)
			assert.Equal(t, tc.wantLease, r.ev.LeaseTime)
		})
	}
}

func TestRequest6GetInnerMessageError(t *testing.T) {
	r := &requestReport{}
	r.request6(&dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward})
	assert.Empty(t, r.ev.Type)
	assert.Empty(t, r.ev.ClientID)
	assert.Empty(t, r.ev.Hostname)
}

func TestShorterLease(t *testing.T) {
	tests := []struct {
		name string
		cur  time.Duration
		next time.Duration
		want time.Duration
	}{
		{name: "zero current takes next", cur: 0, next: time.Hour, want: time.Hour},
		{name: "shorter next replaces current", cur: 2 * time.Hour, next: time.Hour, want: time.Hour},
		{name: "longer next keeps current", cur: time.Hour, next: 2 * time.Hour, want: time.Hour},
		{name: "zero next keeps current", cur: time.Hour, next: 0, want: time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shorterLease(tc.cur, tc.next))
		})
	}
}

func TestAddrFrom(t *testing.T) {
	tests := []struct {
		name   string
		ip     net.IP
		want   netip.Addr
		wantOk bool
	}{
		{
			name:   "ordinary v4 address",
			ip:     net.ParseIP("192.0.2.1"),
			want:   netip.MustParseAddr("192.0.2.1"),
			wantOk: true,
		},
		{
			name:   "ordinary v6 address",
			ip:     net.ParseIP("2001:db8::1"),
			want:   netip.MustParseAddr("2001:db8::1"),
			wantOk: true,
		},
		{
			name: "nil IP becomes the zero Addr",
			ip:   nil,
		},
		{
			name: "malformed IP that is neither 4 nor 16 bytes becomes the zero Addr",
			ip:   net.IP{1, 2, 3},
		},
		{
			name: "IPv4 all-zero becomes the zero Addr",
			ip:   net.IPv4zero,
		},
		{
			name: "IPv6 all-zero becomes the zero Addr",
			ip:   net.IPv6unspecified,
		},
		{
			name: "4-in-6 all-zero becomes the zero Addr",
			ip:   net.ParseIP("::ffff:0.0.0.0"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := addrFrom(tc.ip)
			if !tc.wantOk {
				assert.False(t, got.IsValid())
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCapHostname(t *testing.T) {
	t.Run("shorter than the cap is left alone", func(t *testing.T) {
		assert.Equal(t, "client-1", capHostname("client-1"))
	})

	t.Run("cuts at exactly 255 bytes without sanitising", func(t *testing.T) {
		name := strings.Repeat("a", maxHostname+10)
		got := capHostname(name)
		assert.Len(t, got, maxHostname)
		assert.Equal(t, name[:maxHostname], got)
	})
}

func TestPeerAddrPort(t *testing.T) {
	t.Run("nil peer gives the zero AddrPort", func(t *testing.T) {
		assert.False(t, peerAddrPort(nil).IsValid())
	})

	t.Run("4-in-6 peer is unmapped", func(t *testing.T) {
		got := peerAddrPort(&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 68})
		assert.Equal(t, "192.0.2.1:68", got.String())
	})
}

func TestReplyPath4(t *testing.T) {
	tests := []struct {
		name string
		peer *net.UDPAddr
		want events.ReplyPath
	}{
		{name: "nil peer is unicast", peer: nil, want: events.PathUnicast},
		{name: "broadcast destination", peer: &net.UDPAddr{IP: net.IPv4bcast, Port: 68}, want: events.PathBroadcast},
		{name: "ordinary destination is unicast", peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 68}, want: events.PathUnicast},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, replyPath4(tc.peer))
		})
	}
}

func TestFQDN6(t *testing.T) {
	t.Run("no FQDN option", func(t *testing.T) {
		msg := mustMessage6(t, dhcpv6.MessageTypeRequest)
		assert.Empty(t, fqdn6(msg))
	})

	t.Run("FQDN option with a nil DomainName", func(t *testing.T) {
		msg := mustMessage6(t, dhcpv6.MessageTypeRequest)
		msg.AddOption(&dhcpv6.OptFQDN{DomainName: nil})
		assert.Empty(t, fqdn6(msg))
	})

	t.Run("FQDN option joins its labels", func(t *testing.T) {
		msg := mustMessage6(t, dhcpv6.MessageTypeRequest)
		msg.AddOption(&dhcpv6.OptFQDN{DomainName: &rfc1035label.Labels{Labels: []string{"client", "example", "com"}}})
		assert.Equal(t, "client.example.com", fqdn6(msg))
	})
}
