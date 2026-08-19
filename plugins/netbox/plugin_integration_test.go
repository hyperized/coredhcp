// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build integration

package netbox_test

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/netbox"
)

// integrationEnv reads name from the environment, or skips the test naming
// what it needed.
func integrationEnv(t *testing.T, name, purpose string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s is not set, skipping: %s", name, purpose)
	}
	return v
}

// TestIntegration drives the plugin against a real NetBox instance, over both
// address families, for one MAC the operator has documented there.
//
// It needs NETBOX_URL, NETBOX_TOKEN and NETBOX_TEST_MAC to run at all.
// NETBOX_TEST_IPV4 and NETBOX_TEST_IPV6 are optional: set, they pin down the
// exact address expected back; unset, the test only checks that an address
// of that family came back at all.
func TestIntegration(t *testing.T) {
	const purpose = "exercises Setup4/Setup6 against a real NetBox instance for NETBOX_TEST_MAC"
	url := integrationEnv(t, "NETBOX_URL", purpose)
	token := integrationEnv(t, "NETBOX_TOKEN", purpose)
	macStr := integrationEnv(t, "NETBOX_TEST_MAC", purpose)

	mac, err := net.ParseMAC(macStr)
	require.NoError(t, err)

	wantIPv4 := os.Getenv("NETBOX_TEST_IPV4")
	wantIPv6 := os.Getenv("NETBOX_TEST_IPV6")

	t.Run("Setup4", func(t *testing.T) {
		h4, err := netbox.Plugin.Setup4(url, token)
		require.NoError(t, err)

		req, err := dhcpv4.NewDiscovery(mac)
		require.NoError(t, err)
		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)

		// Handler4 only stops the chain when it actually served an address.
		// YourIPAddr is not a usable signal on its own: NewReplyFromRequest
		// pre-fills it with the unspecified address, so it is never empty.
		gotResp, stop := h4(req, resp)
		require.True(t, stop, "NetBox has no IPv4 address on record for %s", macStr)
		require.NotNil(t, gotResp)
		require.False(t, gotResp.YourIPAddr.IsUnspecified())

		if wantIPv4 != "" {
			require.Equal(t, netip.MustParseAddr(wantIPv4).AsSlice(), []byte(gotResp.YourIPAddr))
		}
	})

	t.Run("Setup6", func(t *testing.T) {
		h6, err := netbox.Plugin.Setup6(url, token)
		require.NoError(t, err)

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		gotResp, _ := h6(req, resp)
		require.NotNil(t, gotResp)
		opts := gotResp.GetOption(dhcpv6.OptionIANA)
		require.Len(t, opts, 1, "expected an IPv6 answer for %s, got none", macStr)

		if wantIPv6 != "" {
			require.Contains(t, opts[0].String(), wantIPv6)
		}
	})
}
