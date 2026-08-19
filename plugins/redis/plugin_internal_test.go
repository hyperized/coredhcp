// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// testKey is the key the handlers look up for testMAC under the default
// prefix.
const testKey = "mac:aa:bb:cc:dd:ee:ff"

// newTestPlugin builds an instance pointed at s without dialling, so a test
// can arrange the server's answers first.
func newTestPlugin(t *testing.T, s *fakeServer, args ...string) *pluginState {
	t.Helper()
	p, err := newPluginState(append([]string{s.addr}, args...)...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.client.Close() })
	return p
}

// v4Exchange builds a request and the reply a previous plugin would have
// started. dhcpv4.NewDiscovery always asks for the DNS option, so the request
// is built by hand here to keep the parameter request list under the test's
// control.
func v4Exchange(t *testing.T, mtype dhcpv4.MessageType, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.New(append([]dhcpv4.Modifier{
		dhcpv4.WithHwAddr(testMAC),
		dhcpv4.WithMessageType(mtype),
	}, mods...)...)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

// v6Exchange builds a request carrying an IA_NA and a DUID the MAC can be
// read from.
func v6Exchange(t *testing.T, mods ...dhcpv6.Modifier) (*dhcpv6.Message, *dhcpv6.Message) {
	t.Helper()
	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, err := dhcpv6.NewMessage(append([]dhcpv6.Modifier{
		dhcpv6.WithClientID(duid),
		dhcpv6.WithIANA(),
	}, mods...)...)
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	return req, resp
}

func TestParseArgsDefaults(t *testing.T) {
	s, err := parseArgs([]string{"10.0.0.9:6379"})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.9:6379", s.client.addr)
	assert.Equal(t, defaultTimeout, s.client.timeout)
	assert.Equal(t, defaultPrefix, s.prefix)
	assert.Equal(t, defaultLifetime, s.lifetime)
	assert.Zero(t, s.client.db)
	assert.Nil(t, s.client.tls)
	assert.Empty(t, s.client.username)
	assert.Empty(t, s.client.password)
}

func TestParseArgsAddress(t *testing.T) {
	cases := []struct {
		name     string
		arg      string
		wantErr  string
		wantAddr string
		wantUser string
		wantPass string
		wantDB   int
		wantTLS  bool
	}{
		{name: "host and port", arg: "10.0.0.9:6379", wantAddr: "10.0.0.9:6379"},
		{name: "IPv6 host", arg: "[2001:db8::1]:6379", wantAddr: "[2001:db8::1]:6379"},
		{name: "URL with a port", arg: "redis://10.0.0.9:6380", wantAddr: "10.0.0.9:6380"},
		{name: "URL without a port", arg: "redis://redis.example.com", wantAddr: "redis.example.com:6379"},
		{
			name: "URL with credentials", arg: "redis://coredhcp:hunter2@10.0.0.9:6379",
			wantAddr: "10.0.0.9:6379", wantUser: "coredhcp", wantPass: "hunter2",
		},
		{
			name: "URL with a password only", arg: "redis://:hunter2@10.0.0.9:6379",
			wantAddr: "10.0.0.9:6379", wantPass: "hunter2",
		},
		{name: "URL with a database", arg: "redis://10.0.0.9:6379/4", wantAddr: "10.0.0.9:6379", wantDB: 4},
		{name: "URL with a trailing slash", arg: "redis://10.0.0.9:6379/", wantAddr: "10.0.0.9:6379"},
		{name: "TLS URL", arg: "rediss://redis.example.com/2", wantAddr: "redis.example.com:6379", wantDB: 2, wantTLS: true},
		{name: "not an address", arg: "10.0.0.9", wantErr: "want host:port"},
		{name: "no host", arg: ":6379", wantErr: "it has no host"},
		{name: "port is not a number", arg: "10.0.0.9:redis", wantErr: "invalid redis port"},
		{name: "port zero", arg: "10.0.0.9:0", wantErr: "invalid redis port"},
		{name: "port out of range", arg: "10.0.0.9:70000", wantErr: "invalid redis port"},
		{name: "URL port out of range", arg: "redis://10.0.0.9:70000", wantErr: "invalid redis port"},
		{name: "unsupported scheme", arg: "http://10.0.0.9:6379", wantErr: "unsupported URL scheme"},
		{name: "URL without a host", arg: "redis:///4", wantErr: "has no host"},
		{name: "database is not a number", arg: "redis://10.0.0.9:6379/main", wantErr: "invalid database"},
		{name: "negative database", arg: "redis://10.0.0.9:6379/-1", wantErr: "invalid database"},
		{name: "database with extra path", arg: "redis://10.0.0.9:6379/4/5", wantErr: "invalid database"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parseArgs([]string{tc.arg})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, s)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAddr, s.client.addr)
			assert.Equal(t, tc.wantUser, s.client.username)
			assert.Equal(t, tc.wantPass, s.client.password)
			assert.Equal(t, tc.wantDB, s.client.db)
			if !tc.wantTLS {
				assert.Nil(t, s.client.tls)
				return
			}
			require.NotNil(t, s.client.tls)
			assert.Equal(t, "redis.example.com", s.client.tls.ServerName)
			assert.Equal(t, uint16(tls.VersionTLS12), s.client.tls.MinVersion)
		})
	}
}

// TestParseArgsURLErrorHidesCredentials covers the one error path that has to
// be careful about what it says: net/url puts the whole URL in its error, and
// the URL may carry a password.
func TestParseArgsURLErrorHidesCredentials(t *testing.T) {
	_, err := parseArgs([]string{"redis://coredhcp:hunter2@ho st:6379"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid redis URL")
	assert.NotContains(t, err.Error(), "hunter2")
}

func TestParseArgsOptions(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, s *settings)
	}{
		{
			name: "password",
			args: []string{"password:hunter2"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "hunter2", s.client.password)
			},
		},
		{
			name: "password from the environment",
			args: []string{"password:env:REDIS_TEST_PASSWORD"},
			env:  map[string]string{"REDIS_TEST_PASSWORD": "hunter2"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "hunter2", s.client.password)
			},
		},
		{
			name: "password overrides the one in the URL",
			args: []string{"password:override"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "override", s.client.password)
			},
		},
		{
			name: "timeout",
			args: []string{"timeout:250ms"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, 250*time.Millisecond, s.client.timeout)
			},
		},
		{
			name: "prefix",
			args: []string{"prefix:dhcp:client:"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, "dhcp:client:", s.prefix)
			},
		},
		{
			name: "empty prefix",
			args: []string{"prefix:"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Empty(t, s.prefix)
			},
		},
		{
			name: "lifetime",
			args: []string{"lifetime:30m"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, 30*time.Minute, s.lifetime)
			},
		},
		{
			name: "every option at once",
			args: []string{"lifetime:2h", "prefix:x:", "timeout:1s", "password:hunter2"},
			check: func(t *testing.T, s *settings) {
				t.Helper()
				assert.Equal(t, 2*time.Hour, s.lifetime)
				assert.Equal(t, "x:", s.prefix)
				assert.Equal(t, time.Second, s.client.timeout)
				assert.Equal(t, "hunter2", s.client.password)
			},
		},
		{name: "unknown argument", args: []string{"bogus:1"}, wantErr: `unknown argument "bogus:1"`},
		{name: "bare argument", args: []string{"autorefresh"}, wantErr: "unknown argument"},
		{name: "empty password", args: []string{"password:"}, wantErr: "password: needs a value"},
		{name: "no variable name", args: []string{"password:env:"}, wantErr: "needs an environment variable name"},
		{name: "unset variable", args: []string{"password:env:REDIS_TEST_PASSWORD"}, wantErr: "is unset or empty"},
		{
			name: "empty variable", args: []string{"password:env:REDIS_TEST_PASSWORD"},
			env: map[string]string{"REDIS_TEST_PASSWORD": ""}, wantErr: "is unset or empty",
		},
		{name: "malformed timeout", args: []string{"timeout:soon"}, wantErr: "invalid timeout:soon"},
		{name: "zero timeout", args: []string{"timeout:0s"}, wantErr: "timeout has to be positive"},
		{name: "negative timeout", args: []string{"timeout:-1s"}, wantErr: "timeout has to be positive"},
		{name: "malformed lifetime", args: []string{"lifetime:forever"}, wantErr: "invalid lifetime:forever"},
		{name: "zero lifetime", args: []string{"lifetime:0"}, wantErr: "lifetime has to be positive"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			s, err := parseArgs(append([]string{"redis://:fromurl@10.0.0.9:6379"}, tc.args...))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, s)
				return
			}
			require.NoError(t, err)
			tc.check(t, s)
		})
	}
}

func TestParseArgsNoAddress(t *testing.T) {
	s, err := parseArgs(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "need a redis address")
	assert.Nil(t, s)
}

func TestSetupState(t *testing.T) {
	t.Run("server answers", func(t *testing.T) {
		s := newFakeServer(t, nil)
		p, err := setupState(s.addr)
		require.NoError(t, err)
		require.NotNil(t, p)
		t.Cleanup(func() { _ = p.client.Close() })
		assert.Equal(t, [][]string{{"PING"}}, s.seen())
	})

	t.Run("server is down", func(t *testing.T) {
		// Setup has to succeed anyway: coredhcp keeps serving its other
		// plugins while redis comes back.
		p, err := setupState("127.0.0.1:1")
		require.NoError(t, err)
		require.NotNil(t, p)
		t.Cleanup(func() { _ = p.client.Close() })
	})

	t.Run("bad arguments", func(t *testing.T) {
		p, err := setupState("nonsense")
		require.Error(t, err)
		assert.Nil(t, p)
	})
}

func TestSetupHandlers(t *testing.T) {
	s := newFakeServer(t, nil)

	h4, err := setup4(s.addr)
	require.NoError(t, err)
	assert.NotNil(t, h4)

	h6, err := setup6(s.addr)
	require.NoError(t, err)
	assert.NotNil(t, h6)

	h4, err = setup4("nonsense")
	require.Error(t, err)
	assert.Nil(t, h4)

	h6, err = setup6("nonsense")
	require.Error(t, err)
	assert.Nil(t, h6)
}

func TestIsKnownField(t *testing.T) {
	for _, name := range []string{fieldIPv4, fieldIPv6, fieldRouter, fieldDNS, fieldLeaseTime} {
		assert.True(t, isKnownField(name), name)
	}
	assert.False(t, isKnownField("hostname"))
}

func TestLookup(t *testing.T) {
	s := newFakeServer(t, nil)
	p := newTestPlugin(t, s, "prefix:dhcp:")
	s.setHash("dhcp:aa:bb:cc:dd:ee:ff", map[string]string{"ipv4": "10.0.0.5", "hostname": "printer"})

	fields, err := p.lookup(testMAC)
	require.NoError(t, err)
	// Unknown fields are handed back untouched; only the handlers decide what
	// to act on.
	assert.Equal(t, map[string]string{"ipv4": "10.0.0.5", "hostname": "printer"}, fields)

	s.replyRaw("HGETALL", "-ERR boom\r\n")
	fields, err = p.lookup(testMAC)
	require.Error(t, err)
	assert.Nil(t, fields)
}

func TestAddressField(t *testing.T) {
	value, ok := addressField(nil, fieldIPv4, testMAC)
	assert.False(t, ok)
	assert.Empty(t, value)

	value, ok = addressField(map[string]string{fieldIPv6: "2001:db8::1"}, fieldIPv4, testMAC)
	assert.False(t, ok)
	assert.Empty(t, value)

	value, ok = addressField(map[string]string{fieldIPv4: "10.0.0.5"}, fieldIPv4, testMAC)
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.5", value)
}

func TestParseIPv4(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		wantAddr string
		wantMask net.IPMask
		wantErr  string
	}{
		{name: "bare address", value: "10.0.0.5", wantAddr: "10.0.0.5"},
		{name: "CIDR", value: "10.0.0.5/24", wantAddr: "10.0.0.5", wantMask: net.CIDRMask(24, 32)},
		{name: "host route", value: "10.0.0.5/32", wantAddr: "10.0.0.5", wantMask: net.CIDRMask(32, 32)},
		{name: "IPv4 mapped", value: "::ffff:10.0.0.5", wantAddr: "10.0.0.5"},
		{name: "empty", value: "", wantErr: "invalid address"},
		{name: "not an address", value: "printer", wantErr: "invalid address"},
		{name: "not a CIDR", value: "10.0.0.5/", wantErr: "invalid CIDR"},
		{name: "IPv6 address", value: "2001:db8::1", wantErr: "not an IPv4 address"},
		{name: "IPv6 CIDR", value: "2001:db8::1/64", wantErr: "not an IPv4 address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, mask, err := parseIPv4(tc.value)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAddr, addr.String())
			assert.Equal(t, tc.wantMask, mask)
		})
	}
}

func TestParseIPv6(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		wantAddr string
		wantErr  string
	}{
		{name: "bare address", value: "2001:db8::10:1", wantAddr: "2001:db8::10:1"},
		{name: "CIDR keeps the address", value: "2001:db8::10:1/64", wantAddr: "2001:db8::10:1"},
		{name: "not an address", value: "printer", wantErr: "invalid address"},
		{name: "IPv4 address", value: "10.0.0.5", wantErr: "not an IPv6 address"},
		{name: "IPv4 mapped", value: "::ffff:10.0.0.5", wantErr: "not an IPv6 address"},
		{name: "IPv4 mapped CIDR", value: "::ffff:10.0.0.5/120", wantErr: "not an IPv6 address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := parseIPv6(tc.value)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAddr, addr.String())
		})
	}
}

func TestDNSServers(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want4 bool
		want  []string
	}{
		{name: "IPv4 entries", value: "10.0.0.2,10.0.0.3", want4: true, want: []string{"10.0.0.2", "10.0.0.3"}},
		{name: "mixed, IPv4 wanted", value: "10.0.0.2,2001:db8::2", want4: true, want: []string{"10.0.0.2"}},
		{name: "mixed, IPv6 wanted", value: "10.0.0.2,2001:db8::2", want: []string{"2001:db8::2"}},
		{name: "whitespace and empty entries", value: " 10.0.0.2 , ,10.0.0.3", want4: true, want: []string{"10.0.0.2", "10.0.0.3"}},
		{name: "invalid entries are skipped", value: "resolver,10.0.0.2", want4: true, want: []string{"10.0.0.2"}},
		{name: "IPv4 mapped counts as IPv4", value: "::ffff:10.0.0.2", want4: true, want: []string{"10.0.0.2"}},
		{name: "nothing usable", value: "2001:db8::2", want4: true, want: []string{}},
		{name: "empty field", value: "", want4: true, want: []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsServers(tc.value, tc.want4)
			names := make([]string, 0, len(got))
			for _, ip := range got {
				names = append(names, ip.String())
			}
			assert.Equal(t, tc.want, names)
		})
	}
}

func TestLeaseTime(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		want   time.Duration
		wantOK bool
	}{
		{name: "absent", fields: map[string]string{}},
		{name: "hours", fields: map[string]string{fieldLeaseTime: "12h"}, want: 12 * time.Hour, wantOK: true},
		{name: "seconds", fields: map[string]string{fieldLeaseTime: "3600s"}, want: time.Hour, wantOK: true},
		{name: "malformed", fields: map[string]string{fieldLeaseTime: "forever"}},
		{name: "zero", fields: map[string]string{fieldLeaseTime: "0s"}},
		{name: "negative", fields: map[string]string{fieldLeaseTime: "-1h"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := leaseTime(tc.fields)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHandler4Inform(t *testing.T) {
	s := newFakeServer(t, nil)
	p := newTestPlugin(t, s)

	req, resp := v4Exchange(t, dhcpv4.MessageTypeInform)
	got, stop := p.Handler4(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
	assert.Empty(t, s.seen(), "an INFORM asks for options, not for a lease, so redis is not consulted")
}

func TestHandler4(t *testing.T) {
	cases := []struct {
		name string
		// requested is the parameter request list of the request. Leaving it
		// empty sends no list at all, which RFC 2131 section 3.5 reads as
		// asking for everything, so a case about an option not being wanted
		// has to send a list that leaves it out.
		requested []dhcpv4.OptionCode
		fields    map[string]string
		raw       string
		wantDrop  bool
		wantPass  bool
		check     func(t *testing.T, resp *dhcpv4.DHCPv4)
	}{
		{name: "unknown MAC passes", wantPass: true},
		{name: "no ipv4 field passes", fields: map[string]string{fieldIPv6: "2001:db8::1"}, wantPass: true},
		{name: "backend error drops", raw: "-ERR boom\r\n", wantDrop: true},
		{name: "malformed reply drops", raw: "+OK\r\n", wantDrop: true},
		{name: "unparseable address drops", fields: map[string]string{fieldIPv4: "printer"}, wantDrop: true},
		{name: "IPv6 in the ipv4 field drops", fields: map[string]string{fieldIPv4: "2001:db8::1"}, wantDrop: true},
		{
			name:   "bare address leaves the mask alone",
			fields: map[string]string{fieldIPv4: "10.0.0.5"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
				assert.Nil(t, resp.SubnetMask())
			},
		},
		{
			name:   "CIDR sets the mask",
			fields: map[string]string{fieldIPv4: "10.0.0.5/24"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
				assert.Equal(t, net.CIDRMask(24, 32), resp.SubnetMask())
			},
		},
		{
			name:   "router",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldRouter: "10.0.0.1"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, []net.IP{net.IP{10, 0, 0, 1}.To4()}, resp.Router())
			},
		},
		{
			name:   "unparseable router is skipped",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldRouter: "gateway"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.Router())
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String(), "the lease survives a bad router")
			},
		},
		{
			name:   "IPv6 router is skipped",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldRouter: "2001:db8::1"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.Router())
			},
		},
		{
			name:      "requested DNS, IPv4 entries only",
			fields:    map[string]string{fieldIPv4: "10.0.0.5", fieldDNS: "10.0.0.2,2001:db8::2,10.0.0.3"},
			requested: []dhcpv4.OptionCode{dhcpv4.OptionDomainNameServer},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, []net.IP{
					net.IP{10, 0, 0, 2}.To4(),
					net.IP{10, 0, 0, 3}.To4(),
				}, resp.DNS())
			},
		},
		{
			name:      "DNS is not offered when the request lists other options",
			fields:    map[string]string{fieldIPv4: "10.0.0.5", fieldDNS: "10.0.0.2"},
			requested: []dhcpv4.OptionCode{dhcpv4.OptionSubnetMask},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.DNS())
			},
		},
		{
			name:      "requested DNS with no usable entry",
			fields:    map[string]string{fieldIPv4: "10.0.0.5", fieldDNS: "2001:db8::2,resolver"},
			requested: []dhcpv4.OptionCode{dhcpv4.OptionDomainNameServer},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.DNS())
			},
		},
		{
			name:   "no parameter request list means DNS is wanted too",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldDNS: "10.0.0.2"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, []net.IP{net.IP{10, 0, 0, 2}.To4()}, resp.DNS())
			},
		},
		{
			name:   "lease time",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldLeaseTime: "12h"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, 12*time.Hour, resp.IPAddressLeaseTime(0))
			},
		},
		{
			name:   "invalid lease time is skipped",
			fields: map[string]string{fieldIPv4: "10.0.0.5", fieldLeaseTime: "forever"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Zero(t, resp.IPAddressLeaseTime(0))
			},
		},
		{
			name: "unknown fields are ignored",
			fields: map[string]string{
				fieldIPv4: "10.0.0.5", fieldIPv6: "2001:db8::1", "hostname": "printer",
			},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t, nil)
			p := newTestPlugin(t, s)
			if tc.fields != nil {
				s.setHash(testKey, tc.fields)
			}
			if tc.raw != "" {
				s.replyRaw("HGETALL", tc.raw)
			}

			var mods []dhcpv4.Modifier
			if len(tc.requested) > 0 {
				mods = append(mods, dhcpv4.WithRequestedOptions(tc.requested...))
			}
			req, resp := v4Exchange(t, dhcpv4.MessageTypeDiscover, mods...)

			got, stop := p.Handler4(req, resp)
			if tc.wantDrop {
				assert.Nil(t, got)
				assert.True(t, stop)
				return
			}
			assert.Same(t, resp, got)
			if tc.wantPass {
				assert.False(t, stop)
				assert.True(t, got.YourIPAddr.IsUnspecified())
				return
			}
			assert.True(t, stop, "a served lease ends the chain")
			tc.check(t, got)
		})
	}
}

func TestHandler6Structure(t *testing.T) {
	s := newFakeServer(t, nil)
	p := newTestPlugin(t, s)
	s.setHash(testKey, map[string]string{fieldIPv6: "2001:db8::10:1"})

	t.Run("cannot decapsulate", func(t *testing.T) {
		req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		got, stop := p.Handler6(req, resp)
		assert.Nil(t, got)
		assert.True(t, stop)
	})

	t.Run("no address requested", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		got, stop := p.Handler6(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
	})

	t.Run("no MAC to look up", func(t *testing.T) {
		// An IA_NA is present but there is no client ID to derive a MAC from.
		req, err := dhcpv6.NewMessage(dhcpv6.WithIANA())
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		got, stop := p.Handler6(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)
		assert.Empty(t, got.GetOption(dhcpv6.OptionIANA))
	})

	assert.Empty(t, s.seen(), "none of these requests should have reached redis")
}

func TestHandler6(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		fields     map[string]string
		raw        string
		requestDNS bool
		wantDrop   bool
		wantPass   bool
		wantAddr   string
		wantLease  time.Duration
		wantDNS    []string
	}{
		{name: "unknown MAC passes", wantPass: true},
		{name: "no ipv6 field passes", fields: map[string]string{fieldIPv4: "10.0.0.5"}, wantPass: true},
		{name: "backend error drops", raw: "-ERR boom\r\n", wantDrop: true},
		{name: "unparseable address drops", fields: map[string]string{fieldIPv6: "printer"}, wantDrop: true},
		{name: "IPv4 in the ipv6 field drops", fields: map[string]string{fieldIPv6: "10.0.0.5"}, wantDrop: true},
		{
			name:      "default lifetime",
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1"},
			wantAddr:  "2001:db8::10:1",
			wantLease: defaultLifetime,
		},
		{
			name:      "lifetime from the configuration",
			args:      []string{"lifetime:30m"},
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1"},
			wantAddr:  "2001:db8::10:1",
			wantLease: 30 * time.Minute,
		},
		{
			name:      "leaseTime wins over the configured lifetime",
			args:      []string{"lifetime:30m"},
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1", fieldLeaseTime: "12h"},
			wantAddr:  "2001:db8::10:1",
			wantLease: 12 * time.Hour,
		},
		{
			name:      "invalid leaseTime falls back to the lifetime",
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1", fieldLeaseTime: "forever"},
			wantAddr:  "2001:db8::10:1",
			wantLease: defaultLifetime,
		},
		{
			name:      "CIDR drops the prefix length",
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1/64"},
			wantAddr:  "2001:db8::10:1",
			wantLease: defaultLifetime,
		},
		{
			name:       "requested DNS, IPv6 entries only",
			fields:     map[string]string{fieldIPv6: "2001:db8::10:1", fieldDNS: "10.0.0.2,2001:db8::2"},
			requestDNS: true,
			wantAddr:   "2001:db8::10:1",
			wantLease:  defaultLifetime,
			wantDNS:    []string{"2001:db8::2"},
		},
		{
			name:      "DNS is not offered unless it was asked for",
			fields:    map[string]string{fieldIPv6: "2001:db8::10:1", fieldDNS: "2001:db8::2"},
			wantAddr:  "2001:db8::10:1",
			wantLease: defaultLifetime,
		},
		{
			name:       "requested DNS with no usable entry",
			fields:     map[string]string{fieldIPv6: "2001:db8::10:1", fieldDNS: "10.0.0.2"},
			requestDNS: true,
			wantAddr:   "2001:db8::10:1",
			wantLease:  defaultLifetime,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t, nil)
			p := newTestPlugin(t, s, tc.args...)
			if tc.fields != nil {
				s.setHash(testKey, tc.fields)
			}
			if tc.raw != "" {
				s.replyRaw("HGETALL", tc.raw)
			}

			var mods []dhcpv6.Modifier
			if tc.requestDNS {
				mods = append(mods, dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer))
			}
			req, resp := v6Exchange(t, mods...)

			got, stop := p.Handler6(req, resp)
			if tc.wantDrop {
				assert.Nil(t, got)
				assert.True(t, stop)
				return
			}
			assert.Same(t, resp, got)
			assert.False(t, stop, "the v6 handler always lets later plugins add their options")
			if tc.wantPass {
				assert.Empty(t, got.GetOption(dhcpv6.OptionIANA))
				return
			}

			iana, ok := got.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
			require.True(t, ok, "want an IA_NA in the response")
			assert.Equal(t, req.Options.OneIANA().IaId, iana.IaId)
			addr := iana.Options.OneAddress()
			require.NotNil(t, addr)
			assert.Equal(t, tc.wantAddr, addr.IPv6Addr.String())
			assert.Equal(t, tc.wantLease, addr.PreferredLifetime)
			assert.Equal(t, tc.wantLease, addr.ValidLifetime)

			names := make([]string, 0, len(resp.Options.DNS()))
			for _, ip := range resp.Options.DNS() {
				names = append(names, ip.String())
			}
			assert.Equal(t, tc.wantDNS, namesOrNil(names))
		})
	}
}

// namesOrNil keeps the table readable: a case that expects no DNS option
// leaves wantDNS unset.
func namesOrNil(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	return names
}
