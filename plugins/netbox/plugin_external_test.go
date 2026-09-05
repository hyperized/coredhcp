// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/netbox"
)

const (
	knownMAC = "aa:bb:cc:dd:ee:ff"

	macFixture      = `{"count":1,"next":null,"previous":null,"results":[{"id":7,"mac_address":"aa:bb:cc:dd:ee:ff","assigned_object_type":"dcim.interface","assigned_object_id":123,"assigned_object":{"id":123,"name":"eth0","device":{"id":1,"name":"sw1"}}}]}`
	macFixtureEmpty = `{"count":0,"next":null,"previous":null,"results":[]}`
	ipFixture       = `{"count":2,"results":[{"id":1,"family":{"value":4,"label":"IPv4"},"address":"10.0.0.5/24","status":{"value":"active","label":"Active"}},{"id":2,"family":{"value":6,"label":"IPv6"},"address":"2001:db8::10:5/64","status":{"value":"active","label":"Active"}}]}`
)

// fakeNetBox reports an Authorization mismatch with t.Errorf, not require.*, since the handler
// runs on its own goroutine where require.* would call runtime.Goexit instead of failing the test.
type fakeNetBox struct {
	srv      *httptest.Server
	wantAuth string
	requests atomic.Int32
}

func newFakeNetBox(t *testing.T, wantAuth string) *fakeNetBox {
	t.Helper()
	f := &fakeNetBox{wantAuth: wantAuth}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/dcim/mac-addresses/", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if got := r.Header.Get("Authorization"); got != f.wantAuth {
			t.Errorf("mac-addresses request: Authorization = %q, want %q", got, f.wantAuth)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("mac_address") == knownMAC {
			_, _ = w.Write([]byte(macFixture))
			return
		}
		_, _ = w.Write([]byte(macFixtureEmpty))
	})
	mux.HandleFunc("/api/ipam/ip-addresses/", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if got := r.Header.Get("Authorization"); got != f.wantAuth {
			t.Errorf("ip-addresses request: Authorization = %q, want %q", got, f.wantAuth)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ipFixture))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func v4Request(t *testing.T, mac net.HardwareAddr) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.NewDiscovery(mac)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

func TestSetup4KnownMAC(t *testing.T) {
	fake := newFakeNetBox(t, "Token secret")
	h4, err := netbox.Plugin.Setup4(fake.srv.URL, "secret")
	require.NoError(t, err)

	mac, err := net.ParseMAC(knownMAC)
	require.NoError(t, err)
	req, resp := v4Request(t, mac)

	gotResp, stop := h4(req, resp)
	assert.Same(t, resp, gotResp)
	assert.True(t, stop)
	assert.Equal(t, net.IP(netip.MustParseAddr("10.0.0.5").AsSlice()), gotResp.YourIPAddr)

	mask := gotResp.SubnetMask()
	require.NotNil(t, mask)
	assert.Equal(t, "255.255.255.0", net.IP(mask).String())
}

func TestSetup4UnknownMAC(t *testing.T) {
	fake := newFakeNetBox(t, "Token secret")
	h4, err := netbox.Plugin.Setup4(fake.srv.URL, "secret")
	require.NoError(t, err)

	mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	req, resp := v4Request(t, mac)

	gotResp, stop := h4(req, resp)
	assert.Same(t, resp, gotResp)
	assert.False(t, stop)
}

func TestSetup6KnownMAC(t *testing.T) {
	fake := newFakeNetBox(t, "Token secret")
	h6, err := netbox.Plugin.Setup6(fake.srv.URL, "secret")
	require.NoError(t, err)

	mac, err := net.ParseMAC(knownMAC)
	require.NoError(t, err)
	req, err := dhcpv6.NewSolicit(mac)
	require.NoError(t, err)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	gotResp, stop := h6(req, resp)
	assert.False(t, stop)
	require.Equal(t, 1, len(gotResp.GetOption(dhcpv6.OptionIANA)))
	opt := gotResp.GetOneOption(dhcpv6.OptionIANA)
	assert.Contains(t, opt.String(), "IP=2001:db8::10:5")
}

// TestCacheKeepsNetBoxOffThePerPacketPath matters because a boot storm retransmits the same MAC
// many times; the second pass here must add no request to the fake server.
func TestCacheKeepsNetBoxOffThePerPacketPath(t *testing.T) {
	fake := newFakeNetBox(t, "Token secret")
	h4, err := netbox.Plugin.Setup4(fake.srv.URL, "secret")
	require.NoError(t, err)

	mac, err := net.ParseMAC(knownMAC)
	require.NoError(t, err)

	runOnce := func() {
		req, resp := v4Request(t, mac)
		_, stop := h4(req, resp)
		assert.True(t, stop)
	}

	runOnce()
	afterFirst := fake.requests.Load()
	assert.Equal(t, int32(2), afterFirst, "a cold lookup should cost one MAC query and one address query")
	runOnce()
	assert.Equal(t, afterFirst, fake.requests.Load())
}

func TestSetupArgErrors(t *testing.T) {
	for _, setup := range []struct {
		name string
		fn   func(args ...string) error
	}{
		{"Setup4", func(args ...string) error { _, err := netbox.Plugin.Setup4(args...); return err }},
		{"Setup6", func(args ...string) error { _, err := netbox.Plugin.Setup6(args...); return err }},
	} {
		t.Run(setup.name, func(t *testing.T) {
			t.Run("no arguments", func(t *testing.T) {
				assert.Error(t, setup.fn())
			})
			t.Run("bad URL", func(t *testing.T) {
				assert.Error(t, setup.fn("ftp://netbox.example.com", "token"))
			})
			t.Run("unknown trailing argument", func(t *testing.T) {
				assert.Error(t, setup.fn("https://netbox.example.com", "token", "bogus"))
			})
		})
	}
}

// TestSetupDoesNotContactNetBox checks setup succeeds regardless, since a DHCP server must come
// up even when NetBox is down or still booting.
func TestSetupDoesNotContactNetBox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s during setup", r.URL.Path)
	}))
	srv.Close() // closed before use, so any request would fail to even connect

	h4, err := netbox.Plugin.Setup4(srv.URL, "secret")
	require.NoError(t, err)
	assert.NotNil(t, h4)

	h6, err := netbox.Plugin.Setup6(srv.URL, "secret")
	require.NoError(t, err)
	assert.NotNil(t, h6)
}

func TestTokenArgument(t *testing.T) {
	t.Run("env: reads the token from the environment", func(t *testing.T) {
		t.Setenv("NETBOX_TEST_TOKEN", "secret")
		fake := newFakeNetBox(t, "Token secret")
		h4, err := netbox.Plugin.Setup4(fake.srv.URL, "env:NETBOX_TEST_TOKEN")
		require.NoError(t, err)

		mac, err := net.ParseMAC(knownMAC)
		require.NoError(t, err)
		req, resp := v4Request(t, mac)

		_, stop := h4(req, resp)
		assert.True(t, stop)
		assert.Greater(t, fake.requests.Load(), int32(0))
	})

	t.Run("an nbt_ token authenticates as a bearer token", func(t *testing.T) {
		fake := newFakeNetBox(t, "Bearer nbt_secret")
		h4, err := netbox.Plugin.Setup4(fake.srv.URL, "nbt_secret")
		require.NoError(t, err)

		mac, err := net.ParseMAC(knownMAC)
		require.NoError(t, err)
		req, resp := v4Request(t, mac)

		_, stop := h4(req, resp)
		assert.True(t, stop)
	})
}
