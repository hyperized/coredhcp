// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasehook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The helper program the exec tests run. The exec target passes no arguments,
// so -test.run cannot be used to select a helper test the usual way; the
// parent steers the child with these variables instead, and TestMain routes
// on them.
const (
	helperModeEnv = "COREDHCP_LEASEHOOK_HELPER"
	helperOutEnv  = "COREDHCP_LEASEHOOK_OUT"

	helperOK     = "ok"
	helperFail   = "fail"
	helperSleep  = "sleep"
	helperStderr = "the hook script did not like that"
)

var (
	testMAC  = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testDUID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: testMAC}
	testTime = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	testXID4 = dhcpv4.TransactionID{0x11, 0x22, 0x33, 0x44}
	testXID6 = dhcpv6.TransactionID{0xaa, 0xbb, 0xcc}
)

// TestMain routes a re-executed test binary to the helper program instead of
// running the tests a second time.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperModeEnv); mode != "" {
		os.Exit(helperMain(mode))
	}
	os.Exit(m.Run())
}

// helperMain is the lease-event program the exec tests point the plugin at.
// One helper covers the three paths worth testing: it records what it was
// sent, fails loudly, or hangs until it is killed.
func helperMain(mode string) int {
	switch mode {
	case helperFail:
		fmt.Fprintln(os.Stderr, helperStderr)
		return 3
	case helperSleep:
		time.Sleep(time.Minute)
		return 0
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 4
	}
	record := map[string]string{"stdin": string(body)}
	for _, name := range []string{"EVENT", "FAMILY", "MAC", "ADDRESSES", "HOSTNAME"} {
		record[name] = os.Getenv(envPrefix + name)
	}
	out, err := json.Marshal(record)
	if err != nil {
		return 5
	}
	if err := os.WriteFile(os.Getenv(helperOutEnv), out, 0o600); err != nil {
		return 6
	}
	return 0
}

// newTestPlugin builds an instance from a config line, with the worker left
// unstarted so a test can look in the queue itself.
func newTestPlugin(t *testing.T, args ...string) *pluginState {
	t.Helper()
	s, err := parseArgs(args)
	require.NoError(t, err)
	return newPluginState(s)
}

// v4Request builds a request carrying the fields the tests share.
func v4Request(t *testing.T, mtype dhcpv4.MessageType, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	req, err := dhcpv4.New(append([]dhcpv4.Modifier{
		dhcpv4.WithTransactionID(testXID4),
		dhcpv4.WithHwAddr(testMAC),
		dhcpv4.WithMessageType(mtype),
	}, mods...)...)
	require.NoError(t, err)
	return req
}

// v4Reply builds the response the rest of the chain would be carrying.
func v4Reply(t *testing.T, req *dhcpv4.DHCPv4, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	resp, err := dhcpv4.NewReplyFromRequest(req, mods...)
	require.NoError(t, err)
	return resp
}

// v6Message builds a DHCPv6 message with a fixed transaction ID, so the
// rendered event is the same on every run.
func v6Message(t *testing.T, mtype dhcpv6.MessageType, mods ...dhcpv6.Modifier) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage(mods...)
	require.NoError(t, err)
	msg.MessageType = mtype
	msg.TransactionID = testXID6
	return msg
}

// mustCIDR parses a prefix for an IA_PD option.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return ipnet
}

func TestEvent4(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4)
		want  string // the JSON body, empty when nothing should be reported
	}{
		{
			name: "offer",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeDiscover,
					dhcpv4.WithGatewayIP(net.IPv4(10, 0, 1, 1)),
					dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
				return req, v4Reply(t, req,
					dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
					dhcpv4.WithYourIP(net.IPv4(10, 0, 0, 5)),
					dhcpv4.WithLeaseTime(3600))
			},
			want: `{"family":4,"event":"offer","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"hostname":"laptop","addresses":["10.0.0.5/32"],"lease_seconds":3600,"relay":"10.0.1.1",` +
				`"transaction_id":"11223344"}`,
		},
		{
			name: "ack",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeRequest,
					dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
				return req, v4Reply(t, req,
					dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
					dhcpv4.WithYourIP(net.IPv4(10, 0, 0, 5)),
					dhcpv4.WithLeaseTime(3600))
			},
			want: `{"family":4,"event":"ack","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"hostname":"laptop","addresses":["10.0.0.5/32"],"lease_seconds":3600,` +
				`"transaction_id":"11223344"}`,
		},
		{
			name: "nak",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeRequest)
				return req, v4Reply(t, req, dhcpv4.WithMessageType(dhcpv4.MessageTypeNak))
			},
			want: `{"family":4,"event":"nak","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"transaction_id":"11223344"}`,
		},
		{
			name: "release reports ciaddr",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeRelease,
					dhcpv4.WithClientIP(net.IPv4(10, 0, 0, 5)))
				// The server answers no RELEASE, so the response the chain
				// carries has no message type at all.
				return req, v4Reply(t, req)
			},
			want: `{"family":4,"event":"release","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"addresses":["10.0.0.5/32"],"transaction_id":"11223344"}`,
		},
		{
			name: "release without ciaddr reports no address",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeRelease)
				return req, v4Reply(t, req)
			},
			want: `{"family":4,"event":"release","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"transaction_id":"11223344"}`,
		},
		{
			name: "decline reports the address in option 50",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeDecline,
					dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.IPv4(10, 0, 0, 6))))
				return req, v4Reply(t, req)
			},
			want: `{"family":4,"event":"decline","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"addresses":["10.0.0.6/32"],"transaction_id":"11223344"}`,
		},
		{
			name: "an offer without an address is not reported",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeDiscover)
				return req, v4Reply(t, req, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
			},
		},
		{
			name: "an inform is not reported",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeInform)
				return req, v4Reply(t, req, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
			},
		},
		{
			name: "a response with no message type is not reported",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				req := v4Request(t, dhcpv4.MessageTypeRequest)
				return req, v4Reply(t, req)
			},
		},
		{
			name: "a dropped response is not reported",
			build: func(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
				t.Helper()
				return v4Request(t, dhcpv4.MessageTypeDiscover), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := tc.build(t)
			ev, ok := event4(req, resp, testTime)
			if tc.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			body, err := json.Marshal(ev)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(body))
		})
	}
}

func TestEvent6(t *testing.T) {
	address := dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2001:db8::5"),
		PreferredLifetime: 30 * time.Minute,
		ValidLifetime:     time.Hour,
	}
	prefix := &dhcpv6.OptIAPrefix{
		Prefix:            mustCIDR(t, "2001:db8:1::/64"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
	}

	for _, tc := range []struct {
		name  string
		build func(*testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6)
		want  string
	}{
		{
			name: "reply with an address and a delegated prefix",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest,
					dhcpv6.WithClientID(testDUID),
					dhcpv6.WithFQDN(0, "laptop.lan"))
				resp := v6Message(t, dhcpv6.MessageTypeReply,
					dhcpv6.WithIANA(address),
					dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, prefix))
				return req, resp
			},
			want: `{"family":6,"event":"reply","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","hostname":"laptop.lan","addresses":["2001:db8::5/128"],` +
				`"prefixes":["2001:db8:1::/64"],"lease_seconds":3600,"transaction_id":"aabbcc"}`,
		},
		{
			name: "a delegation without an address takes its lifetime from the prefix",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
				resp := v6Message(t, dhcpv6.MessageTypeReply,
					dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, prefix))
				return req, resp
			},
			want: `{"family":6,"event":"reply","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","prefixes":["2001:db8:1::/64"],"lease_seconds":7200,` +
				`"transaction_id":"aabbcc"}`,
		},
		{
			name: "an empty prefix option is skipped",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
				resp := v6Message(t, dhcpv6.MessageTypeReply,
					dhcpv6.WithIANA(address),
					dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, &dhcpv6.OptIAPrefix{}))
				return req, resp
			},
			want: `{"family":6,"event":"reply","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","addresses":["2001:db8::5/128"],"lease_seconds":3600,` +
				`"transaction_id":"aabbcc"}`,
		},
		{
			name: "a relayed reply names the link the client is on",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
				relayed, err := dhcpv6.EncapsulateRelay(req, dhcpv6.MessageTypeRelayForward,
					net.ParseIP("2001:db8:ff::1"), net.ParseIP("fe80::1"))
				require.NoError(t, err)
				resp := v6Message(t, dhcpv6.MessageTypeReply, dhcpv6.WithIANA(address))
				return relayed, resp
			},
			want: `{"family":6,"event":"reply","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","addresses":["2001:db8::5/128"],"lease_seconds":3600,` +
				`"relay":"2001:db8:ff::1","transaction_id":"aabbcc"}`,
		},
		{
			name: "release reports what the client hands back",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRelease,
					dhcpv6.WithClientID(testDUID),
					dhcpv6.WithIANA(address))
				return req, v6Message(t, dhcpv6.MessageTypeReply)
			},
			want: `{"family":6,"event":"release","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","addresses":["2001:db8::5/128"],"transaction_id":"aabbcc"}`,
		},
		{
			name: "decline reports what the client refuses",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeDecline,
					dhcpv6.WithClientID(testDUID),
					dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, prefix))
				return req, v6Message(t, dhcpv6.MessageTypeReply)
			},
			want: `{"family":6,"event":"decline","time":"2026-09-05T12:00:00Z","mac":"aa:bb:cc:dd:ee:ff",` +
				`"duid":"00030001aabbccddeeff","prefixes":["2001:db8:1::/64"],"transaction_id":"aabbcc"}`,
		},
		{
			name: "a reply that leases nothing is not reported",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
				resp := v6Message(t, dhcpv6.MessageTypeReply,
					dhcpv6.WithIANA(dhcpv6.OptIAAddress{}))
				return req, resp
			},
		},
		{
			name: "an advertise is not reported",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeSolicit, dhcpv6.WithClientID(testDUID))
				return req, v6Message(t, dhcpv6.MessageTypeAdvertise, dhcpv6.WithIANA(address))
			},
		},
		{
			name: "a dropped response is not reported",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				return v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID)), nil
			},
		},
		{
			name: "a request that will not decapsulate is not reported",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				return &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward},
					v6Message(t, dhcpv6.MessageTypeReply, dhcpv6.WithIANA(address))
			},
		},
		{
			name: "a response that will not decapsulate is not reported",
			build: func(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
				t.Helper()
				req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
				return req, &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayReply}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := tc.build(t)
			ev, ok := event6(req, resp, testTime)
			if tc.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			body, err := json.Marshal(ev)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(body))
		})
	}
}

func TestFQDN6(t *testing.T) {
	t.Run("no option", func(t *testing.T) {
		assert.Empty(t, fqdn6(v6Message(t, dhcpv6.MessageTypeRequest)))
	})
	t.Run("an option without a name", func(t *testing.T) {
		msg := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithOption(&dhcpv6.OptFQDN{}))
		assert.Empty(t, fqdn6(msg))
	})
	t.Run("a name", func(t *testing.T) {
		msg := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithFQDN(0, "laptop.lan"))
		assert.Equal(t, "laptop.lan", fqdn6(msg))
	})
}

func TestRelayLinkAddr(t *testing.T) {
	t.Run("a message that came in directly has no relay", func(t *testing.T) {
		assert.Nil(t, relayLinkAddr(v6Message(t, dhcpv6.MessageTypeRequest)))
	})
	t.Run("a relay that will not decapsulate still names its link", func(t *testing.T) {
		relay := &dhcpv6.RelayMessage{
			MessageType: dhcpv6.MessageTypeRelayForward,
			LinkAddr:    net.ParseIP("2001:db8:ff::1"),
		}
		assert.Equal(t, "2001:db8:ff::1", relayLinkAddr(relay).String())
	})
	t.Run("nested relays report the one closest to the client", func(t *testing.T) {
		msg := v6Message(t, dhcpv6.MessageTypeRequest)
		inner, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward,
			net.ParseIP("2001:db8:ff::1"), net.ParseIP("fe80::1"))
		require.NoError(t, err)
		outer, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward,
			net.ParseIP("2001:db8:ee::1"), net.ParseIP("fe80::2"))
		require.NoError(t, err)
		assert.Equal(t, "2001:db8:ff::1", relayLinkAddr(outer).String())
	})
}

func TestTruncateUTF8(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "shorter than the limit", in: "laptop", max: 255, want: "laptop"},
		{name: "exactly the limit", in: strings.Repeat("a", 255), max: 255, want: strings.Repeat("a", 255)},
		{name: "cut on a rune boundary", in: strings.Repeat("a", 260), max: 255, want: strings.Repeat("a", 255)},
		{
			name: "backs off one byte of a two byte rune",
			in:   strings.Repeat("a", 254) + "é",
			max:  255,
			want: strings.Repeat("a", 254),
		},
		{
			name: "backs off two bytes of a four byte rune",
			in:   strings.Repeat("a", 253) + "\U0001f600",
			max:  255,
			want: strings.Repeat("a", 253),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, truncateUTF8(tc.in, tc.max))
		})
	}
}

func TestSanitizeEnv(t *testing.T) {
	assert.Equal(t, "laptop", sanitizeEnv("laptop"))
	assert.Equal(t, "a_b_c_d", sanitizeEnv("a\nb\x00c\x7fd"))
}

func TestStderrSuffix(t *testing.T) {
	assert.Empty(t, stderrSuffix(nil))
	assert.Equal(t, ", stderr: boom", stderrSuffix([]byte("  boom\n")))
}

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
		check   func(*testing.T, *settings)
	}{
		{
			name: "a webhook with every option",
			args: []string{"url:https://ipam.example/hook", "secret:s3cr3t", "timeout:5s", "queue:10", "events:ack,release"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "https://ipam.example/hook", s.url)
				assert.Equal(t, []byte("s3cr3t"), s.secret)
				assert.Equal(t, 5*time.Second, s.timeout)
				assert.Equal(t, 10, s.queue)
				assert.Equal(t, map[string]bool{eventAck: true, eventRelease: true}, s.events)
				assert.Equal(t, "ack,release", s.eventList())
				assert.Equal(t, "https://ipam.example/hook", s.describe())
				assert.IsType(t, &webhook{}, s.newTarget())
			},
		},
		{
			name: "a program, with the defaults",
			args: []string{"exec:/usr/local/bin/lease-event"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "/usr/local/bin/lease-event", s.path)
				assert.Equal(t, defaultTimeout, s.timeout)
				assert.Equal(t, defaultQueue, s.queue)
				assert.Equal(t, knownEvents, s.events)
				assert.Equal(t, "offer,ack,nak,reply,release,decline", s.eventList())
				assert.Equal(t, "/usr/local/bin/lease-event", s.describe())
				assert.IsType(t, &command{}, s.newTarget())
			},
		},
		{
			name: "a password in the URL is kept out of the log",
			args: []string{"url:https://user:hunter2@ipam.example/hook"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "https://user:hunter2@ipam.example/hook", s.url)
				assert.NotContains(t, s.describe(), "hunter2")
			},
		},
		{name: "no target", args: nil, wantErr: "need one of url:"},
		{
			name:    "both targets",
			args:    []string{"url:https://ipam.example/hook", "exec:/bin/true"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "a secret without a webhook",
			args:    []string{"exec:/bin/true", "secret:s3cr3t"},
			wantErr: "has no meaning",
		},
		{name: "an unusable URL", args: []string{"url:://ipam.example"}, wantErr: "invalid webhook URL"},
		{name: "a URL that is not http", args: []string{"url:ftp://ipam.example/hook"}, wantErr: "unsupported URL scheme"},
		{name: "a URL without a host", args: []string{"url:http:///hook"}, wantErr: "no host"},
		{name: "a relative program path", args: []string{"exec:bin/lease-event"}, wantErr: "absolute path"},
		{name: "an empty secret", args: []string{"url:http://h/x", "secret:"}, wantErr: "secret: needs a value"},
		{
			name:    "a secret naming no variable",
			args:    []string{"url:http://h/x", "secret:env:"},
			wantErr: "needs an environment variable name",
		},
		{
			name:    "a secret from an unset variable",
			args:    []string{"url:http://h/x", "secret:env:COREDHCP_LEASEHOOK_MISSING"},
			wantErr: "is unset or empty",
		},
		{name: "an unparseable timeout", args: []string{"exec:/bin/true", "timeout:soon"}, wantErr: "invalid timeout:"},
		{name: "a timeout of zero", args: []string{"exec:/bin/true", "timeout:0s"}, wantErr: "has to be positive"},
		{name: "an unparseable queue", args: []string{"exec:/bin/true", "queue:lots"}, wantErr: "invalid queue:"},
		{name: "a queue of zero", args: []string{"exec:/bin/true", "queue:0"}, wantErr: "invalid queue:"},
		{name: "an unknown event", args: []string{"exec:/bin/true", "events:renew"}, wantErr: `unknown event "renew"`},
		{name: "an empty event list", args: []string{"exec:/bin/true", "events:"}, wantErr: `unknown event ""`},
		{name: "an unknown argument", args: []string{"exec:/bin/true", "retries:3"}, wantErr: `unknown argument "retries:3"`},
		{
			name:    "a repeated argument",
			args:    []string{"url:http://h/x", "timeout:1s", "timeout:2s"},
			wantErr: "timeout given more than once",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parseArgs(tc.args)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			tc.check(t, s)
		})
	}
}

func TestApplySecretFromEnvironment(t *testing.T) {
	t.Setenv("COREDHCP_LEASEHOOK_SECRET", "s3cr3t")
	s, err := parseArgs([]string{"url:http://h/x", "secret:env:COREDHCP_LEASEHOOK_SECRET"})
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), s.secret)
}

// fakeTarget stands in for a webhook or a program, so the worker can be
// driven without either.
type fakeTarget struct {
	delivered chan delivery
	err       error
}

func (f *fakeTarget) deliver(_ context.Context, d delivery) error {
	f.delivered <- d
	return f.err
}

func TestEnqueue(t *testing.T) {
	ack := event{Family: familyV4, Event: eventAck}

	t.Run("an event the allow-list leaves out is not queued", func(t *testing.T) {
		p := newTestPlugin(t, "exec:/bin/true", "events:release")
		p.enqueue(ack)
		assert.Empty(t, p.queue)
	})

	t.Run("a full queue drops and counts", func(t *testing.T) {
		p := newTestPlugin(t, "exec:/bin/true", "queue:1")
		p.enqueue(ack)
		p.enqueue(ack)
		assert.Len(t, p.queue, 1)
		assert.Equal(t, uint64(1), p.drops)
	})

	t.Run("an event that will not serialise is dropped", func(t *testing.T) {
		p := newTestPlugin(t, "exec:/bin/true")
		original := marshalEvent
		marshalEvent = func(any) ([]byte, error) { return nil, errors.New("no") }
		t.Cleanup(func() { marshalEvent = original })
		p.enqueue(ack)
		assert.Empty(t, p.queue)
	})
}

func TestCountDrop(t *testing.T) {
	now := testTime
	p := &pluginState{now: func() time.Time { return now }}

	total, warn := p.countDrop()
	assert.Equal(t, uint64(1), total)
	assert.True(t, warn, "the first drop is worth a line")

	now = now.Add(time.Second)
	total, warn = p.countDrop()
	assert.Equal(t, uint64(2), total)
	assert.False(t, warn, "a second drop within the interval is not")

	now = now.Add(2 * dropWarnInterval)
	_, warn = p.countDrop()
	assert.True(t, warn, "once the interval has passed it is again")

	p.dropped()
}

func TestTimeNowFallsBackToTheWallClock(t *testing.T) {
	assert.WithinDuration(t, time.Now(), (&pluginState{}).timeNow(), time.Minute)
}

func TestWorker(t *testing.T) {
	p := newTestPlugin(t, "exec:/bin/true")
	fake := &fakeTarget{delivered: make(chan delivery, 2), err: errors.New("the endpoint said no")}
	p.target = fake
	go p.run()

	req := v4Request(t, dhcpv4.MessageTypeRequest)
	resp := v4Reply(t, req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(net.IPv4(10, 0, 0, 5)))
	got, stop := p.Handler4(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop, "the plugin never ends the chain")

	select {
	case d := <-fake.delivered:
		assert.Equal(t, eventAck, d.ev.Event)
	case <-time.After(10 * time.Second):
		t.Fatal("the event was never delivered")
	}

	// stopWorker blocks until the goroutine is gone, so a worker that did not
	// notice would fail this test by timing out.
	p.stopWorker()
}

func TestHandlersIgnoreWhatIsNotAnEvent(t *testing.T) {
	p := newTestPlugin(t, "exec:/bin/true")

	req4 := v4Request(t, dhcpv4.MessageTypeInform)
	resp4 := v4Reply(t, req4, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	got4, stop4 := p.Handler4(req4, resp4)
	assert.Same(t, resp4, got4)
	assert.False(t, stop4)

	req6 := v6Message(t, dhcpv6.MessageTypeSolicit, dhcpv6.WithClientID(testDUID))
	resp6 := v6Message(t, dhcpv6.MessageTypeAdvertise)
	got6, stop6 := p.Handler6(req6, resp6)
	assert.Same(t, resp6, got6)
	assert.False(t, stop6)

	assert.Empty(t, p.queue)
}

func TestHandler6QueuesAReply(t *testing.T) {
	p := newTestPlugin(t, "exec:/bin/true")
	req := v6Message(t, dhcpv6.MessageTypeRequest, dhcpv6.WithClientID(testDUID))
	resp := v6Message(t, dhcpv6.MessageTypeReply, dhcpv6.WithIANA(dhcpv6.OptIAAddress{
		IPv6Addr:      net.ParseIP("2001:db8::5"),
		ValidLifetime: time.Hour,
	}))
	got, stop := p.Handler6(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
	require.Len(t, p.queue, 1)
	assert.Equal(t, eventReply, (<-p.queue).ev.Event)
}

func TestSetupState(t *testing.T) {
	t.Run("bad arguments never start a worker", func(t *testing.T) {
		p, err := setupState("queue:nope")
		require.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("a program target", func(t *testing.T) {
		p, err := setupState("exec:/bin/true", "events:ack")
		require.NoError(t, err)
		t.Cleanup(p.stopWorker)
		assert.IsType(t, &command{}, p.target)
	})
	t.Run("a webhook target", func(t *testing.T) {
		p, err := setupState("url:http://ipam.example/hook")
		require.NoError(t, err)
		t.Cleanup(p.stopWorker)
		assert.IsType(t, &webhook{}, p.target)
	})
}

// received is one request the test endpoint was sent.
type received struct {
	body   []byte
	header http.Header
}

// newRecorder starts an endpoint answering with status, and reports what it
// was sent on the returned channel.
func newRecorder(t *testing.T, status int) (*httptest.Server, <-chan received) {
	t.Helper()
	got := make(chan received, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request body: %v", err)
			return
		}
		got <- received{body: body, header: r.Header.Clone()}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestWebhookDeliver(t *testing.T) {
	payload := []byte(`{"family":4,"event":"ack"}`)
	d := delivery{payload: payload, ev: event{Family: familyV4, Event: eventAck}}

	t.Run("posts the body and signs it", func(t *testing.T) {
		srv, got := newRecorder(t, http.StatusNoContent)
		w := newWebhook(srv.URL, []byte("s3cr3t"))
		require.NoError(t, w.deliver(t.Context(), d))

		req := <-got
		assert.Equal(t, payload, req.body)
		assert.Equal(t, contentType, req.header.Get("Content-Type"))
		// Recomputed here rather than pasted in, which is what a receiver
		// has to do anyway.
		assert.Equal(t, sign([]byte("s3cr3t"), payload), req.header.Get(signatureHeader))
		assert.True(t, strings.HasPrefix(req.header.Get(signatureHeader), signaturePrefix))
	})

	t.Run("without a secret there is no signature", func(t *testing.T) {
		srv, got := newRecorder(t, http.StatusOK)
		w := newWebhook(srv.URL, nil)
		require.NoError(t, w.deliver(t.Context(), d))
		assert.Empty(t, (<-got).header.Get(signatureHeader))
	})

	t.Run("a non-2xx answer is an error naming the status", func(t *testing.T) {
		srv, _ := newRecorder(t, http.StatusInternalServerError)
		w := newWebhook(srv.URL, nil)
		err := w.deliver(t.Context(), d)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("a slow endpoint runs into the timeout", func(t *testing.T) {
		// The handler blocks until the test lets it go. Cleanups run last in
		// first out, so release is closed before the server is, and Close
		// does not sit waiting on a handler that will never return.
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			<-release
		}))
		t.Cleanup(srv.Close)
		t.Cleanup(func() { close(release) })

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		err := newWebhook(srv.URL, nil).deliver(ctx, d)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "posting the event")
	})

	t.Run("an endpoint that is not there is an error", func(t *testing.T) {
		srv, _ := newRecorder(t, http.StatusOK)
		url := srv.URL
		srv.Close()
		err := newWebhook(url, nil).deliver(t.Context(), d)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "posting the event")
	})

	t.Run("a URL no request can be built from is an error", func(t *testing.T) {
		// parseArgs refuses this at setup, so only a hand-built webhook can
		// reach the branch.
		err := (&webhook{url: "://ipam.example", hc: &http.Client{}}).deliver(t.Context(), d)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "building the request")
	})
}

func TestCommandDeliver(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	d := delivery{
		payload: []byte(`{"family":4,"event":"ack"}`),
		ev: event{
			Family:    familyV4,
			Event:     eventAck,
			MAC:       testMAC.String(),
			Hostname:  "lap\ntop",
			Addresses: []string{"10.0.0.5/32", "10.0.0.6/32"},
		},
	}

	t.Run("the event arrives on stdin and in the environment", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "event.json")
		t.Setenv(helperModeEnv, helperOK)
		t.Setenv(helperOutEnv, out)

		require.NoError(t, (&command{path: self}).deliver(t.Context(), d))

		raw, err := os.ReadFile(out)
		require.NoError(t, err)
		var got map[string]string
		require.NoError(t, json.Unmarshal(raw, &got))

		assert.JSONEq(t, string(d.payload), got["stdin"])
		assert.Equal(t, eventAck, got["EVENT"])
		assert.Equal(t, "4", got["FAMILY"])
		assert.Equal(t, testMAC.String(), got["MAC"])
		assert.Equal(t, "10.0.0.5/32 10.0.0.6/32", got["ADDRESSES"])
		assert.Equal(t, "lap_top", got["HOSTNAME"], "control characters never reach the program")
	})

	t.Run("a non-zero exit is an error carrying stderr", func(t *testing.T) {
		t.Setenv(helperModeEnv, helperFail)
		err := (&command{path: self}).deliver(t.Context(), d)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 3")
		assert.Contains(t, err.Error(), helperStderr)
	})

	t.Run("a program that hangs runs into the timeout", func(t *testing.T) {
		t.Setenv(helperModeEnv, helperSleep)
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		require.Error(t, (&command{path: self}).deliver(ctx, d))
	})
}
