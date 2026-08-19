// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package macfilter_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpiana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/macfilter"
)

var (
	listedMAC   = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	unlistedMAC = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
)

func v4Exchange(t *testing.T, mac net.HardwareAddr) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.NewDiscovery(mac)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

func v6ExchangeWithMAC(t *testing.T, mac net.HardwareAddr) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
	t.Helper()
	duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: mac}
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	return req, resp
}

func v6ExchangeWithoutMAC(t *testing.T) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
	t.Helper()
	// No ClientID option is set, so dhcpv6.ExtractMAC cannot derive a MAC
	// from either a DUID-LL/DUID-LLT or a relay link-layer option.
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	return req, resp
}

func TestSetup4Errors(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup4()
		assert.Error(t, err)
	})

	t.Run("invalid mode", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup4("perhaps", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
	})

	t.Run("no MACs", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup4("allow")
		assert.Error(t, err)
	})

	t.Run("invalid MAC", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup4("allow", "not-a-mac")
		assert.Error(t, err)
	})
}

func TestSetup6Errors(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup6()
		assert.Error(t, err)
	})

	t.Run("invalid mode", func(t *testing.T) {
		_, err := macfilter.Plugin.Setup6("perhaps", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
	})
}

func TestHandler4(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		mac      net.HardwareAddr
		wantDrop bool
	}{
		{"allow mode passes a listed MAC", "allow", listedMAC, false},
		{"allow mode drops an unlisted MAC", "allow", unlistedMAC, true},
		{"deny mode drops a listed MAC", "deny", listedMAC, true},
		{"deny mode passes an unlisted MAC", "deny", unlistedMAC, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := macfilter.Plugin.Setup4(tc.mode, listedMAC.String())
			require.NoError(t, err)

			req, resp := v4Exchange(t, tc.mac)
			gotResp, stop := h4(req, resp)

			if tc.wantDrop {
				assert.Nil(t, gotResp)
				assert.True(t, stop)
				return
			}
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
		})
	}
}

func TestHandler6(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		mac      net.HardwareAddr
		wantDrop bool
	}{
		{"allow mode passes a listed MAC", "allow", listedMAC, false},
		{"allow mode drops an unlisted MAC", "allow", unlistedMAC, true},
		{"deny mode drops a listed MAC", "deny", listedMAC, true},
		{"deny mode passes an unlisted MAC", "deny", unlistedMAC, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h6, err := macfilter.Plugin.Setup6(tc.mode, listedMAC.String())
			require.NoError(t, err)

			req, resp := v6ExchangeWithMAC(t, tc.mac)
			gotResp, stop := h6(req, resp)

			if tc.wantDrop {
				assert.Nil(t, gotResp)
				assert.True(t, stop)
				return
			}
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
		})
	}
}

func TestHandler6NoMACAsymmetry(t *testing.T) {
	t.Run("allow mode fails closed and drops", func(t *testing.T) {
		h6, err := macfilter.Plugin.Setup6("allow", listedMAC.String())
		require.NoError(t, err)

		req, resp := v6ExchangeWithoutMAC(t)
		gotResp, stop := h6(req, resp)

		assert.Nil(t, gotResp)
		assert.True(t, stop)
	})

	t.Run("deny mode cannot condemn and passes", func(t *testing.T) {
		h6, err := macfilter.Plugin.Setup6("deny", listedMAC.String())
		require.NoError(t, err)

		req, resp := v6ExchangeWithoutMAC(t)
		gotResp, stop := h6(req, resp)

		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
	})
}

func TestFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "macs.txt")
	require.NoError(t, os.WriteFile(path, []byte("# comment\n"+listedMAC.String()+"\n"), 0o600))

	h4, err := macfilter.Plugin.Setup4("deny", "file:"+path)
	require.NoError(t, err)

	req, resp := v4Exchange(t, listedMAC)
	gotResp, stop := h4(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)

	req, resp = v4Exchange(t, unlistedMAC)
	gotResp, stop = h4(req, resp)
	assert.Same(t, resp, gotResp)
	assert.False(t, stop)
}
