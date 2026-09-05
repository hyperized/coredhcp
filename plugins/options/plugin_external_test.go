// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package options_test

import (
	"net"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/options"
)

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// reply4 builds a DHCPv4 request/stub pair; the request asks for nothing.
func reply4(t *testing.T) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.NewDiscovery(testMAC)
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, stub
}

// reply6 is reply4's DHCPv6 counterpart; NewReplyFromMessage refuses a plain Solicit, hence WithRapidCommit.
func reply6(t *testing.T) (*dhcpv6.Message, dhcpv6.DHCPv6) {
	t.Helper()
	req, err := dhcpv6.NewSolicit(testMAC, dhcpv6.WithRapidCommit)
	require.NoError(t, err)
	stub, err := dhcpv6.NewReplyFromMessage(req)
	require.NoError(t, err)
	return req, stub
}

func ip6(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s)
	require.NotNil(t, ip)
	return ip.To16()
}

func TestPlugin(t *testing.T) {
	assert.Equal(t, "options", options.Plugin.Name)
	assert.NotNil(t, options.Plugin.Setup4)
	assert.NotNil(t, options.Plugin.Setup6)
}

func TestSetup4Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", args: nil, want: "at least one"},
		{name: "missing fields", args: []string{"15:string"}, want: "code:type:value"},
		{name: "code zero", args: []string{"0:string:pad"}, want: "pad option"},
		{name: "code beyond a byte", args: []string{"256:string:x"}, want: "want 1-255"},
		{name: "code not a number", args: []string{"fifteen:string:x"}, want: "invalid option code"},
		{name: "unknown type", args: []string{"15:str:home.lan"}, want: "unknown type"},
		{name: "empty value", args: []string{"15:string:"}, want: "empty option value"},
		{name: "v6 address in v4", args: []string{"42:ip:2001:db8::1"}, want: "IPv4"},
		{name: "odd hex", args: []string{"43:hex:abc"}, want: "invalid hex value"},
		{name: "second spec invalid", args: []string{"15:string:home.lan", "42:ip:nope"}, want: `"42:ip:nope"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := options.Plugin.Setup4(tc.args...)
			assert.Nil(t, h4)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestSetup6Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", args: nil, want: "at least one"},
		{name: "code zero", args: []string{"0:string:pad"}, want: "pad option"},
		{name: "code beyond two bytes", args: []string{"65536:string:x"}, want: "invalid option code"},
		{name: "v4 address in v6", args: []string{"31:ip:192.0.2.10"}, want: "IPv6"},
		{name: "v4 address in a v6 list", args: []string{"23:iplist:2001:db8::53,192.0.2.53"}, want: "IPv6"},
		{name: "bad bool", args: []string{"7:bool:maybe"}, want: "invalid bool value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h6, err := options.Plugin.Setup6(tc.args...)
			assert.Nil(t, h6)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Runs the documented example config lines end to end, as the config loader would parse them.
func TestSetup4Config(t *testing.T) {
	for _, tc := range []struct {
		name string
		// line is the plugin entry as it appears in config.yml.
		line string
		want map[uint8][]byte
	}{
		{
			name: "domain name and ntp server",
			line: "15:string:home.lan 42:ip:192.0.2.10",
			want: map[uint8][]byte{
				15: []byte("home.lan"),
				42: {192, 0, 2, 10},
			},
		},
		{
			name: "wpad url with colons",
			line: "252:string:http://192.0.2.1:8080/wpad.dat",
			want: map[uint8][]byte{252: []byte("http://192.0.2.1:8080/wpad.dat")},
		},
		{
			name: "dns list and ipv6-only preference",
			line: "6:iplist:192.0.2.53,192.0.2.54 108:uint32:300",
			want: map[uint8][]byte{
				6:   {192, 0, 2, 53, 192, 0, 2, 54},
				108: {0x00, 0x00, 0x01, 0x2c},
			},
		},
		{
			name: "flag and raw vendor bytes",
			line: "19:bool:true 43:hex:0104c0a80001",
			want: map[uint8][]byte{
				19: {0x01},
				43: {0x01, 0x04, 0xc0, 0xa8, 0x00, 0x01},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := options.Plugin.Setup4(strings.Fields(tc.line)...)
			require.NoError(t, err)
			require.NotNil(t, h4)

			req, stub := reply4(t)
			resp, stop := h4(req, stub)
			require.NotNil(t, resp)
			assert.False(t, stop)

			for code, want := range tc.want {
				assert.Equal(t, want, resp.Options.Get(dhcpv4.GenericOptionCode(code)), "option %d", code)
			}
			// The reply must still serialise cleanly with the new options.
			assert.NotEmpty(t, resp.ToBytes())
		})
	}
}

func TestSetup6Config(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want map[uint16][]byte
	}{
		{
			name: "dns servers and sntp server",
			line: "23:iplist:2001:db8::53,2001:db8::54 31:ip:2001:db8::123",
			want: map[uint16][]byte{
				23: append(ip6(t, "2001:db8::53"), ip6(t, "2001:db8::54")...),
				31: ip6(t, "2001:db8::123"),
			},
		},
		{
			name: "bootfile url with colons",
			line: "59:string:http://[2001:db8::1]/boot.ipxe",
			want: map[uint16][]byte{59: []byte("http://[2001:db8::1]/boot.ipxe")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h6, err := options.Plugin.Setup6(strings.Fields(tc.line)...)
			require.NoError(t, err)
			require.NotNil(t, h6)

			req, stub := reply6(t)
			resp, stop := h6(req, stub)
			require.NotNil(t, resp)
			assert.False(t, stop)

			for code, want := range tc.want {
				opt := resp.GetOneOption(dhcpv6.OptionCode(code))
				require.NotNil(t, opt, "option %d", code)
				assert.Equal(t, want, opt.ToBytes(), "option %d", code)
			}
			assert.NotEmpty(t, resp.ToBytes())
		})
	}
}

// Consistent with the dns and router plugins: options are served regardless of the client's request list.
func TestSetup4IgnoresParameterRequestList(t *testing.T) {
	h4, err := options.Plugin.Setup4("114:string:https://example.com/portal")
	require.NoError(t, err)

	req, err := dhcpv4.NewDiscovery(testMAC, dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask))
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := h4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Equal(t, []byte("https://example.com/portal"), resp.Options.Get(dhcpv4.GenericOptionCode(114)))
}

func TestSetup6IgnoresOptionRequest(t *testing.T) {
	h6, err := options.Plugin.Setup6("31:ip:2001:db8::123")
	require.NoError(t, err)

	req, err := dhcpv6.NewSolicit(testMAC, dhcpv6.WithRapidCommit, dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer))
	require.NoError(t, err)
	stub, err := dhcpv6.NewReplyFromMessage(req)
	require.NoError(t, err)

	resp, stop := h6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	opt := resp.GetOneOption(dhcpv6.OptionCode(31))
	require.NotNil(t, opt)
	assert.Equal(t, ip6(t, "2001:db8::123"), opt.ToBytes())
}

func TestSetup4RepeatedCodeLastWins(t *testing.T) {
	h4, err := options.Plugin.Setup4("15:string:first.lan", "15:string:second.lan")
	require.NoError(t, err)

	req, stub := reply4(t)
	resp, _ := h4(req, stub)
	require.NotNil(t, resp)
	assert.Equal(t, "second.lan", dhcpv4.GetString(dhcpv4.OptionDomainName, resp.Options))
}
