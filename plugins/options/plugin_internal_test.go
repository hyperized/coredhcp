// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package options

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ip6 is a shorthand for the sixteen-byte form of an IPv6 address.
func ip6(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s)
	require.NotNil(t, ip)
	return ip.To16()
}

// mustRequest6 builds a DHCPv6 request that NewReplyFromMessage accepts. A
// plain Solicit is refused unless it carries the rapid-commit option.
func mustRequest6(t *testing.T) *dhcpv6.Message {
	t.Helper()
	req, err := dhcpv6.NewSolicit(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, dhcpv6.WithRapidCommit)
	require.NoError(t, err)
	return req
}

func TestParseAddr4(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		want    []byte
		wantErr bool
	}{
		{name: "dotted quad", value: "192.0.2.10", want: []byte{192, 0, 2, 10}},
		{name: "v4-mapped v6 literal", value: "::ffff:192.0.2.10", want: []byte{192, 0, 2, 10}},
		{name: "v6 address", value: "2001:db8::1", wantErr: true},
		{name: "hostname", value: "gateway.lan", wantErr: true},
		{name: "empty", value: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAddr4(tc.value)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "IPv4")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseAddr6(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		want    []byte
		wantErr bool
	}{
		{name: "global unicast", value: "2001:db8::1", want: ip6(t, "2001:db8::1")},
		{name: "link local", value: "fe80::1", want: ip6(t, "fe80::1")},
		{name: "v4 literal", value: "192.0.2.10", wantErr: true},
		{name: "v4-mapped literal", value: "::ffff:192.0.2.10", wantErr: true},
		{name: "garbage", value: "not-an-address", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAddr6(tc.value)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "IPv6")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValueParsers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     string
		fam     *family
		value   string
		want    []byte
		wantErr bool
	}{
		{name: "string", typ: "string", fam: family4, value: "home.lan", want: []byte("home.lan")},
		{name: "string keeps colons", typ: "string", fam: family4, value: "http://192.0.2.1:8080/wpad.dat", want: []byte("http://192.0.2.1:8080/wpad.dat")},
		{name: "ip v4", typ: "ip", fam: family4, value: "192.0.2.10", want: []byte{192, 0, 2, 10}},
		{name: "ip v4 invalid", typ: "ip", fam: family4, value: "192.0.2.999", wantErr: true},
		{name: "ip v6", typ: "ip", fam: family6, value: "2001:db8::1", want: ip6(t, "2001:db8::1")},
		{name: "ip v6 invalid", typ: "ip", fam: family6, value: "2001:db8::/32", wantErr: true},
		{name: "iplist v4 single", typ: "iplist", fam: family4, value: "192.0.2.53", want: []byte{192, 0, 2, 53}},
		{name: "iplist v4 multiple", typ: "iplist", fam: family4, value: "192.0.2.53,192.0.2.54", want: []byte{192, 0, 2, 53, 192, 0, 2, 54}},
		{name: "iplist v4 empty element", typ: "iplist", fam: family4, value: "192.0.2.53,", wantErr: true},
		{name: "iplist v6", typ: "iplist", fam: family6, value: "2001:db8::53,2001:db8::54", want: append(ip6(t, "2001:db8::53"), ip6(t, "2001:db8::54")...)},
		{name: "iplist v6 bad element", typ: "iplist", fam: family6, value: "2001:db8::53,192.0.2.54", wantErr: true},
		{name: "uint8 min", typ: "uint8", fam: family4, value: "0", want: []byte{0x00}},
		{name: "uint8 max", typ: "uint8", fam: family4, value: "255", want: []byte{0xff}},
		{name: "uint8 overflow", typ: "uint8", fam: family4, value: "256", wantErr: true},
		{name: "uint8 not a number", typ: "uint8", fam: family4, value: "many", wantErr: true},
		{name: "uint16", typ: "uint16", fam: family4, value: "1500", want: []byte{0x05, 0xdc}},
		{name: "uint16 max", typ: "uint16", fam: family4, value: "65535", want: []byte{0xff, 0xff}},
		{name: "uint16 overflow", typ: "uint16", fam: family4, value: "65536", wantErr: true},
		{name: "uint32", typ: "uint32", fam: family4, value: "300", want: []byte{0x00, 0x00, 0x01, 0x2c}},
		{name: "uint32 max", typ: "uint32", fam: family4, value: "4294967295", want: []byte{0xff, 0xff, 0xff, 0xff}},
		{name: "uint32 overflow", typ: "uint32", fam: family4, value: "4294967296", wantErr: true},
		{name: "uint32 negative", typ: "uint32", fam: family4, value: "-1", wantErr: true},
		{name: "hex", typ: "hex", fam: family4, value: "0104c0a80001", want: []byte{0x01, 0x04, 0xc0, 0xa8, 0x00, 0x01}},
		{name: "hex uppercase", typ: "hex", fam: family6, value: "DEADBEEF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "hex odd length", typ: "hex", fam: family4, value: "abc", wantErr: true},
		{name: "hex non-hex digit", typ: "hex", fam: family4, value: "zz", wantErr: true},
		{name: "bool true", typ: "bool", fam: family4, value: "true", want: []byte{0x01}},
		{name: "bool one", typ: "bool", fam: family4, value: "1", want: []byte{0x01}},
		{name: "bool false", typ: "bool", fam: family4, value: "false", want: []byte{0x00}},
		{name: "bool zero", typ: "bool", fam: family6, value: "0", want: []byte{0x00}},
		{name: "bool invalid", typ: "bool", fam: family4, value: "yes please", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse, ok := valueParsers[tc.typ]
			require.True(t, ok)

			got, err := parse(tc.fam, tc.value)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestKnownTypes(t *testing.T) {
	assert.Equal(t, "bool, hex, ip, iplist, string, uint16, uint32, uint8", knownTypes())
}

func TestParseCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fam     *family
		raw     string
		want    uint16
		wantErr error
	}{
		{name: "v4 lowest", fam: family4, raw: "1", want: 1},
		{name: "v4 highest", fam: family4, raw: "255", want: 255},
		{name: "v4 above range", fam: family4, raw: "256"},
		{name: "v4 zero", fam: family4, raw: "0", wantErr: errZeroCode},
		{name: "v6 highest", fam: family6, raw: "65535", want: 65535},
		{name: "v6 above range", fam: family6, raw: "65536"},
		{name: "v6 zero", fam: family6, raw: "0", wantErr: errZeroCode},
		{name: "not a number", fam: family4, raw: "0x2a"},
		{name: "negative", fam: family4, raw: "-1"},
		{name: "empty", fam: family4, raw: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCode(tc.fam, tc.raw)
			if tc.want == 0 {
				require.Error(t, err)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseSpec(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fam     *family
		arg     string
		want    spec
		wantErr error
	}{
		{name: "string", fam: family4, arg: "15:string:home.lan", want: spec{code: 15, data: []byte("home.lan")}},
		{name: "value keeps every later colon", fam: family6, arg: "31:ip:2001:db8::123", want: spec{code: 31, data: ip6(t, "2001:db8::123")}},
		{name: "url value", fam: family4, arg: "114:string:http://192.0.2.1:8080/p", want: spec{code: 114, data: []byte("http://192.0.2.1:8080/p")}},
		{name: "no colon", fam: family4, arg: "15", wantErr: errMalformedSpec},
		{name: "one colon", fam: family4, arg: "15:string", wantErr: errMalformedSpec},
		{name: "empty spec", fam: family4, arg: "", wantErr: errMalformedSpec},
		{name: "empty value", fam: family4, arg: "15:string:", wantErr: errEmptyValue},
		{name: "zero code", fam: family4, arg: "0:string:pad", wantErr: errZeroCode},
		{name: "code out of range", fam: family4, arg: "256:string:x"},
		{name: "unknown type", fam: family4, arg: "15:str:home.lan"},
		{name: "value rejected by parser", fam: family4, arg: "42:ip:nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSpec(tc.fam, tc.arg)
			if tc.want.code == 0 {
				require.Error(t, err)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseSpecUnknownTypeNamesTheAllowList(t *testing.T) {
	_, err := parseSpec(family4, "15:str:home.lan")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown type "str"`)
	assert.Contains(t, err.Error(), knownTypes())
}

func TestParseSpecs(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		_, err := parseSpecs(family4, nil)
		assert.ErrorIs(t, err, errNoSpecs)
	})

	t.Run("order is preserved", func(t *testing.T) {
		got, err := parseSpecs(family4, []string{"15:string:home.lan", "42:ip:192.0.2.10", "108:uint32:300"})
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, []spec{
			{code: 15, data: []byte("home.lan")},
			{code: 42, data: []byte{192, 0, 2, 10}},
			{code: 108, data: []byte{0x00, 0x00, 0x01, 0x2c}},
		}, got)
	})

	t.Run("error names the offending spec", func(t *testing.T) {
		_, err := parseSpecs(family6, []string{"23:iplist:2001:db8::53", "0:string:pad"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"0:string:pad"`)
		assert.ErrorIs(t, err, errZeroCode)
	})
}

func TestPluginStateHandler4(t *testing.T) {
	p := &pluginState{opts4: []dhcpv4.Option{
		dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(15), []byte("home.lan")),
		dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(42), []byte{192, 0, 2, 10}),
	}}

	// No parameter request list at all: the options must be set regardless.
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	resp, stop := p.Handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Equal(t, []byte("home.lan"), resp.Options.Get(dhcpv4.GenericOptionCode(15)))
	assert.Equal(t, []byte{192, 0, 2, 10}, resp.Options.Get(dhcpv4.GenericOptionCode(42)))
}

func TestPluginStateHandler4Overwrites(t *testing.T) {
	p := &pluginState{opts4: []dhcpv4.Option{
		dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(15), []byte("home.lan")),
	}}

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	stub.Options.Update(dhcpv4.OptDomainName("set-by-an-earlier-plugin"))

	resp, stop := p.Handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Equal(t, "home.lan", dhcpv4.GetString(dhcpv4.OptionDomainName, resp.Options))
}

func TestPluginStateHandler4NoOptions(t *testing.T) {
	p := &pluginState{}

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	stub, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	before := len(stub.Options)

	resp, stop := p.Handler4(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Len(t, resp.Options, before)
}

func TestPluginStateHandler6(t *testing.T) {
	p := &pluginState{specs6: []spec{
		{code: 23, data: append(ip6(t, "2001:db8::53"), ip6(t, "2001:db8::54")...)},
		{code: 31, data: ip6(t, "2001:db8::123")},
	}}

	req := mustRequest6(t)
	stub, err := dhcpv6.NewReplyFromMessage(req)
	require.NoError(t, err)

	resp, stop := p.Handler6(req, stub)
	require.NotNil(t, resp)
	assert.False(t, stop)

	got := resp.GetOneOption(dhcpv6.OptionCode(23))
	require.NotNil(t, got)
	assert.Equal(t, append(ip6(t, "2001:db8::53"), ip6(t, "2001:db8::54")...), got.ToBytes())

	got = resp.GetOneOption(dhcpv6.OptionCode(31))
	require.NotNil(t, got)
	assert.Equal(t, ip6(t, "2001:db8::123"), got.ToBytes())
}

// TestPluginStateHandler6DoesNotShareOptions guards the reason Handler6 builds
// an OptionGeneric per response instead of reusing a prebuilt one: a DHCPv6
// message keeps the pointer it is handed, so two responses in flight would
// otherwise alias the same struct.
func TestPluginStateHandler6DoesNotShareOptions(t *testing.T) {
	p := &pluginState{specs6: []spec{{code: 31, data: ip6(t, "2001:db8::123")}}}

	responses := make([]dhcpv6.Option, 0, 2)
	for range 2 {
		req := mustRequest6(t)
		stub, err := dhcpv6.NewReplyFromMessage(req)
		require.NoError(t, err)

		resp, _ := p.Handler6(req, stub)
		opt := resp.GetOneOption(dhcpv6.OptionCode(31))
		require.NotNil(t, opt)
		responses = append(responses, opt)
	}

	assert.NotSame(t, responses[0], responses[1])
	assert.Equal(t, responses[0].ToBytes(), responses[1].ToBytes())
}
