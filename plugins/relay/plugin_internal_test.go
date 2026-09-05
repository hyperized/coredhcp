// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package relay

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
)

// fakeClock is the seam the drop limiter reads time through, so the tests
// step over the rate-limit interval instead of sleeping across it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// captureLog redirects the shared logger to a buffer for the duration of the
// test. The logger's console writer is process-wide, so a test using this may
// not run in parallel with another one that logs.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logger.WithConsole(&buf)
	t.Cleanup(func() { logger.WithConsole(os.Stderr) })
	return &buf
}

// nestedRelay wraps an empty client message in depth Relay-forward layers.
func nestedRelay(t *testing.T, depth int, linkAddr net.IP) *dhcpv6.RelayMessage {
	t.Helper()
	inner, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	var msg dhcpv6.DHCPv6 = inner
	for range depth {
		relay, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward, linkAddr, net.ParseIP("fe80::1"))
		require.NoError(t, err)
		msg = relay
	}
	relay, ok := msg.(*dhcpv6.RelayMessage)
	require.True(t, ok)
	return relay
}

func TestSetupState(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		wantErr      error
		wantErrText  string
		wantAllow4   []string
		wantAllow6   []string
		wantStrict   bool
		wantRelCheck bool
	}{
		{
			name:    "no arguments",
			args:    nil,
			wantErr: errNoAllowKeyword,
		},
		{
			name:    "first argument is not allow",
			args:    []string{"deny", "10.0.1.1"},
			wantErr: errNoAllowKeyword,
		},
		{
			name:    "allow with no entries",
			args:    []string{"allow"},
			wantErr: errNoAllowEntries,
		},
		{
			name:    "only options after allow",
			args:    []string{"allow", "strict-giaddr", "release-check:off"},
			wantErr: errNoAllowEntries,
		},
		{
			name:         "single IPv4 address",
			args:         []string{"allow", "10.0.1.1"},
			wantAllow4:   []string{"10.0.1.1/32"},
			wantRelCheck: true,
		},
		{
			name:         "IPv4 prefix is masked",
			args:         []string{"allow", "10.0.2.5/24"},
			wantAllow4:   []string{"10.0.2.0/24"},
			wantRelCheck: true,
		},
		{
			name:         "both families on one line",
			args:         []string{"allow", "10.0.1.1", "10.0.2.0/24", "fe80::/10", "2001:db8::1"},
			wantAllow4:   []string{"10.0.1.1/32", "10.0.2.0/24"},
			wantAllow6:   []string{"fe80::/10", "2001:db8::1/128"},
			wantRelCheck: true,
		},
		{
			name:         "options before and after the entries",
			args:         []string{"allow", "strict-giaddr", "10.0.1.1", "release-check:off"},
			wantAllow4:   []string{"10.0.1.1/32"},
			wantStrict:   true,
			wantRelCheck: false,
		},
		{
			name:         "release-check on is the default spelled out",
			args:         []string{"allow", "10.0.1.1", "release-check:on"},
			wantAllow4:   []string{"10.0.1.1/32"},
			wantRelCheck: true,
		},
		{
			name:        "repeated strict-giaddr",
			args:        []string{"allow", "10.0.1.1", "strict-giaddr", "strict-giaddr"},
			wantErr:     errRepeatedOption,
			wantErrText: "strict-giaddr",
		},
		{
			name:        "repeated release-check",
			args:        []string{"allow", "10.0.1.1", "release-check:on", "release-check:off"},
			wantErr:     errRepeatedOption,
			wantErrText: "release-check",
		},
		{
			name:        "invalid release-check value",
			args:        []string{"allow", "10.0.1.1", "release-check:maybe"},
			wantErrText: `invalid release-check value "maybe"`,
		},
		{
			name:        "invalid address",
			args:        []string{"allow", "not-an-address"},
			wantErrText: `invalid address "not-an-address"`,
		},
		{
			name:        "invalid prefix",
			args:        []string{"allow", "10.0.0.0/99"},
			wantErrText: `invalid prefix "10.0.0.0/99"`,
		},
		{
			name:        "zoned prefix",
			args:        []string{"allow", "fe80::1%eth0/64"},
			wantErrText: `invalid prefix "fe80::1%eth0/64"`,
		},
		{
			name:        "IPv4-mapped address",
			args:        []string{"allow", "::ffff:10.0.1.1"},
			wantErr:     errMappedEntry,
			wantErrText: `address "::ffff:10.0.1.1"`,
		},
		{
			name:        "IPv4-mapped prefix",
			args:        []string{"allow", "::ffff:10.0.1.0/120"},
			wantErr:     errMappedEntry,
			wantErrText: `prefix "::ffff:10.0.1.0/120"`,
		},
		{
			name:        "zoned address",
			args:        []string{"allow", "fe80::1%eth0"},
			wantErr:     errZonedEntry,
			wantErrText: `address "fe80::1%eth0"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := setupState(tc.args...)
			if tc.wantErr != nil || tc.wantErrText != "" {
				require.Error(t, err)
				assert.Nil(t, p)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
				}
				if tc.wantErrText != "" {
					assert.Contains(t, err.Error(), tc.wantErrText)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)
			assert.Equal(t, tc.wantAllow4, prefixStrings(p.allow4))
			assert.Equal(t, tc.wantAllow6, prefixStrings(p.allow6))
			assert.Equal(t, tc.wantStrict, p.strictGiaddr)
			assert.Equal(t, tc.wantRelCheck, p.releaseCheck)
			assert.NotNil(t, p.limiter)
		})
	}
}

// prefixStrings renders a prefix list for comparison, returning nil for an
// empty one so the table can leave the field out.
func prefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

func TestPacketAddr(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		want string
		ok   bool
	}{
		{name: "nil", ip: nil},
		{name: "four zero bytes", ip: net.IP{0, 0, 0, 0}},
		{name: "unspecified in 16-byte form", ip: net.IPv4zero},
		{name: "wrong length", ip: net.IP{1, 2, 3}},
		{name: "dotted quad", ip: net.IP{10, 0, 1, 1}, want: "10.0.1.1", ok: true},
		{name: "IPv4 in 16-byte form", ip: net.ParseIP("10.0.1.1"), want: "10.0.1.1", ok: true},
		{name: "IPv6", ip: net.ParseIP("2001:db8::1"), want: "2001:db8::1", ok: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := packetAddr(tc.ip)
			assert.Equal(t, tc.ok, ok)
			if !tc.ok {
				assert.False(t, addr.IsValid())
				return
			}
			assert.Equal(t, tc.want, addr.String())
		})
	}
}

func TestPeerAddrUnmaps(t *testing.T) {
	info := handler.RequestInfo{Peer: netip.MustParseAddrPort("[::ffff:10.0.1.1]:67")}
	assert.Equal(t, "10.0.1.1", peerAddr(info).String())
}

func TestAllowed(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.1/32"),
		netip.MustParsePrefix("10.0.2.0/24"),
	}
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{name: "exact host entry", addr: "10.0.1.1", want: true},
		{name: "inside the prefix", addr: "10.0.2.99", want: true},
		{name: "outside every entry", addr: "10.0.3.1"},
		{name: "other family", addr: "2001:db8::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, allowed(prefixes, netip.MustParseAddr(tc.addr)))
		})
	}
}

func TestAllowedRejectsInvalidAddress(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	assert.False(t, allowed(prefixes, netip.Addr{}))
}

func TestUnspecifiedLink(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{name: "absent", ip: nil, want: true},
		{name: "unspecified", ip: net.IPv6zero, want: true},
		{name: "a real link address", ip: net.ParseIP("2001:db8::1")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unspecifiedLink(tc.ip))
		})
	}
}

func TestRelayDepth(t *testing.T) {
	cases := []struct {
		name  string
		depth int
		want  int
	}{
		{name: "single relay", depth: 1, want: 1},
		{name: "two relays", depth: 2, want: 2},
		{name: "at the limit", depth: maxRelayDepth, want: maxRelayDepth},
		{name: "one past the limit", depth: maxRelayDepth + 1, want: maxRelayDepth + 1},
		{name: "walk stops one past the limit", depth: 20, want: maxRelayDepth + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, relayDepth(nestedRelay(t, tc.depth, net.ParseIP("2001:db8::1"))))
		})
	}
}

func TestRelayDepthWithoutInnerMessage(t *testing.T) {
	// A Relay-forward carrying no Relay-Message option cannot be decoded any
	// further, and the walk stops rather than looping.
	relay := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
	assert.Equal(t, 1, relayDepth(relay))
}

func TestDropLimiter(t *testing.T) {
	clock := newFakeClock()
	limiter := newDropLimiter(clock.now)

	assert.True(t, limiter.allow(reasonGiaddrNotAllowed), "first line for a reason is always allowed")
	assert.False(t, limiter.allow(reasonGiaddrNotAllowed), "second line inside the interval is held back")

	assert.True(t, limiter.allow(reasonRelayDepth), "another reason has its own budget")

	clock.advance(logInterval - time.Nanosecond)
	assert.False(t, limiter.allow(reasonGiaddrNotAllowed), "still inside the interval")

	clock.advance(time.Nanosecond)
	assert.True(t, limiter.allow(reasonGiaddrNotAllowed), "the interval has passed")
}

func TestLogDropRateLimits(t *testing.T) {
	buf := captureLog(t)
	clock := newFakeClock()
	p := &pluginState{limiter: newDropLimiter(clock.now)}

	for range 100 {
		p.logDrop(reasonGiaddrNotAllowed, "giaddr %s", "10.9.9.9")
	}
	assert.Equal(t, 1, strings.Count(buf.String(), "giaddr not in the allow list"))
	assert.Contains(t, buf.String(), "10.9.9.9")

	clock.advance(logInterval)
	p.logDrop(reasonGiaddrNotAllowed, "giaddr %s", "10.9.9.9")
	assert.Equal(t, 2, strings.Count(buf.String(), "giaddr not in the allow list"))
}

func TestLogDropIsConcurrencySafe(t *testing.T) {
	captureLog(t)
	p := &pluginState{limiter: newDropLimiter(time.Now)}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				p.logDrop(reasonPeerNotAllowed, "source %s", "fe80::1")
			}
		}()
	}
	wg.Wait()
}
