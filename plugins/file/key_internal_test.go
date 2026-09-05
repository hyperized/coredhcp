// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		want    keyMode
		wantErr string
	}{
		{name: "mac", raw: "mac", want: keyMAC},
		{name: "duid", raw: "duid", want: keyDUID},
		{name: "client-id", raw: "client-id", want: keyClientID},
		{name: "unknown value", raw: "bogus", wantErr: `unknown key "bogus"`},
		{name: "empty value", raw: "", wantErr: `unknown key ""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseKeyMode(tc.raw)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestKeyModeLabel(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode keyMode
		want string
	}{
		{name: "mac", mode: keyMAC, want: "MAC address"},
		{name: "duid", mode: keyDUID, want: "DUID"},
		{name: "client-id", mode: keyClientID, want: "client identifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.mode.label())
		})
	}
}

func TestKeyModeCheckFamily(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        keyMode
		v6          bool
		errContains string
	}{
		{name: "mac allowed on v4", mode: keyMAC, v6: false},
		{name: "mac allowed on v6", mode: keyMAC, v6: true},
		{name: "duid allowed on v6", mode: keyDUID, v6: true},
		{name: "duid rejected on v4", mode: keyDUID, v6: false, errContains: "key:duid"},
		{name: "client-id allowed on v4", mode: keyClientID, v6: false},
		{name: "client-id rejected on v6", mode: keyClientID, v6: true, errContains: "key:client-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mode.checkFamily(tc.v6)
			if tc.errContains == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestParseHexBytes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          string
		wantHex     string
		wantErr     bool
		errContains string
	}{
		{name: "0x prefix lowercase", in: "0xaabbcc", wantHex: "aabbcc"},
		{name: "0x prefix uppercase", in: "0xAABBCC", wantHex: "aabbcc"},
		{name: "colon separated lowercase", in: "aa:bb:cc", wantHex: "aabbcc"},
		{name: "colon separated uppercase", in: "AA:BB:CC", wantHex: "aabbcc"},
		{name: "mixed case no separator", in: "AaBbCc", wantHex: "aabbcc"},
		{name: "0x prefix with colons", in: "0xAA:bb:CC", wantHex: "aabbcc"},
		{name: "empty string", in: "", wantErr: true, errContains: "no hexadecimal digits"},
		{name: "just the 0x prefix", in: "0x", wantErr: true, errContains: "no hexadecimal digits"},
		{name: "just colons", in: ":::", wantErr: true, errContains: "no hexadecimal digits"},
		{name: "odd length", in: "abc", wantErr: true},
		{name: "non-hex digit", in: "zz", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseHexBytes(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHex, hex.EncodeToString(got))
		})
	}
}

func TestParseMACField(t *testing.T) {
	for _, tc := range []struct {
		name    string
		field   string
		want    string
		wantErr bool
	}{
		{name: "lowercase", field: "aa:bb:cc:dd:ee:ff", want: "aa:bb:cc:dd:ee:ff"},
		{name: "uppercase folds to lowercase", field: "AA:BB:CC:DD:EE:FF", want: "aa:bb:cc:dd:ee:ff"},
		{name: "malformed", field: "not-a-mac", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMACField(tc.field)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "malformed hardware address")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseDUIDField(t *testing.T) {
	// One octet past the RFC 8415 cap plus the two-octet type code.
	tooLong := strings.Repeat("aa", maxDUIDLen+1)

	for _, tc := range []struct {
		name        string
		field       string
		want        string
		wantErr     bool
		errContains string
	}{
		{name: "0x prefix", field: "0x00030001aabbccddeeff", want: "00030001aabbccddeeff"},
		{name: "colon separated", field: "00:03:00:01:aa:bb:cc:dd:ee:ff", want: "00030001aabbccddeeff"},
		{name: "uppercase no separator", field: "00030001AABBCCDDEEFF", want: "00030001aabbccddeeff"},
		{name: "malformed hex", field: "0xzz", wantErr: true, errContains: "malformed DUID"},
		{name: "over the length cap", field: tooLong, wantErr: true, errContains: fmt.Sprintf("%d octets", maxDUIDLen+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDUIDField(tc.field)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseClientIDField(t *testing.T) {
	for _, tc := range []struct {
		name        string
		field       string
		want        string
		wantErr     bool
		errContains string
	}{
		{name: "hex with 0x prefix", field: "0x01aabbccddeeff", want: "01aabbccddeeff"},
		{name: "hex colon separated", field: "01:aa:bb:cc:dd:ee:ff", want: "01aabbccddeeff"},
		{name: "hex uppercase", field: "01AABBCCDDEEFF", want: "01aabbccddeeff"},
		{name: "text form", field: "text:printer-2nd-floor", want: hex.EncodeToString([]byte("printer-2nd-floor"))},
		{name: "empty text form", field: "text:", wantErr: true, errContains: "empty text: client identifier"},
		{name: "malformed hex", field: "0xzz", wantErr: true, errContains: "malformed client identifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseClientIDField(tc.field)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestKeyModeParseKeyField only has to prove the mode dispatches to the right
// helper; each helper's own edge cases are covered above.
func TestKeyModeParseKeyField(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  keyMode
		field string
		want  string
	}{
		{name: "mac", mode: keyMAC, field: "AA:BB:CC:DD:EE:FF", want: "aa:bb:cc:dd:ee:ff"},
		{name: "duid", mode: keyDUID, field: "0x00030001aabbccddeeff", want: "00030001aabbccddeeff"},
		{name: "client-id", mode: keyClientID, field: "text:foo", want: hex.EncodeToString([]byte("foo"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.mode.parseKeyField(tc.field)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestKey4(t *testing.T) {
	mac, err := net.ParseMAC("aa:11:22:33:44:55")
	require.NoError(t, err)

	t.Run("mac mode always keys on the hardware address", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{ClientHWAddr: mac}
		key, ok := keyMAC.key4(req)
		assert.True(t, ok)
		assert.Equal(t, "aa:11:22:33:44:55", key)
	})

	t.Run("client-id mode with option 61", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{ClientHWAddr: mac}
		req.UpdateOption(dhcpv4.OptClientIdentifier([]byte{0x01, 0xaa, 0xbb}))
		key, ok := keyClientID.key4(req)
		assert.True(t, ok)
		assert.Equal(t, "01aabb", key)
	})

	t.Run("client-id mode with no option 61 passes through", func(t *testing.T) {
		req := &dhcpv4.DHCPv4{ClientHWAddr: mac}
		_, ok := keyClientID.key4(req)
		assert.False(t, ok)
	})
}

func TestKey6(t *testing.T) {
	mac, err := net.ParseMAC("aa:11:22:33:44:55")
	require.NoError(t, err)

	t.Run("mac mode extracts the link-layer address", func(t *testing.T) {
		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		key, ok := keyMAC.key6(req, req)
		assert.True(t, ok)
		assert.Equal(t, mac.String(), key)
	})

	t.Run("mac mode with no extractable MAC passes through", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		_, ok := keyMAC.key6(req, req)
		assert.False(t, ok)
	})

	t.Run("duid mode dispatches to duidKey", func(t *testing.T) {
		duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}
		req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
		require.NoError(t, err)
		key, ok := keyDUID.key6(req, req)
		assert.True(t, ok)
		assert.Equal(t, hex.EncodeToString(duid.ToBytes()), key)
	})
}

func TestDuidKey(t *testing.T) {
	t.Run("no client ID passes through", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		_, ok := duidKey(msg)
		assert.False(t, ok)
	})

	t.Run("valid DUID resolves", func(t *testing.T) {
		duid := &dhcpv6.DUIDLL{
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: net.HardwareAddr{0xaa, 0x11, 0x22, 0x33, 0x44, 0x55},
		}
		msg, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
		require.NoError(t, err)
		key, ok := duidKey(msg)
		assert.True(t, ok)
		assert.Equal(t, hex.EncodeToString(duid.ToBytes()), key)
	})

	t.Run("DUID over the length cap passes through", func(t *testing.T) {
		duid := &dhcpv6.DUIDEN{EnterpriseNumber: 1, EnterpriseIdentifier: make([]byte, 200)}
		msg, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
		require.NoError(t, err)
		_, ok := duidKey(msg)
		assert.False(t, ok)
	})
}
