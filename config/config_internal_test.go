// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config

import (
	"errors"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitHostPort(t *testing.T) {
	testcases := []struct {
		name     string
		hostport string
		ip       string
		zone     string
		port     string
		wantErr  bool
	}{
		{"v4 with port", "0.0.0.0:67", "0.0.0.0", "", "67", false},
		{"v4 no port", "192.0.2.0", "192.0.2.0", "", "", false},
		{"v4 zoned no port", "192.0.2.9%eth0", "192.0.2.9", "eth0", "", false},
		{"v4 zoned with port", "0.0.0.0%eth0:67", "0.0.0.0", "eth0", "67", false},
		{"v4 zone/port ambiguous", "0.0.0.0:20%eth0:67", "0.0.0.0", "eth0", "67", true},
		{"v6 unbracketed with port is invalid", "2001:db8::1:547", "", "", "547", true},
		{"v6 bracketed, no zone", "[::]:547", "::", "", "547", false},
		{"v6 bracketed, zoned, no port", "[fe80::1%eth0]", "fe80::1", "eth0", "", false},
		{"v6 bracketed, garbage after ] read as port", "[fe80::1]:eth1", "fe80::1", "", "eth1", false},
		{"v6 zoned with port, no brackets, invalid", "fe80::1%eth0:547", "fe80::1", "eth0", "547", true},
		{"v6 zoned, no brackets, no port, invalid", "fe80::1%eth0", "fe80::1", "eth0", "547", true},
		{"garbage after brackets", "[2001:db8::2]47", "fe80::1", "eth0", "547", true},
		{"ss-style zone with port", "[ff02::1:2]%srv_u:547", "ff02::1:2", "srv_u", "547", false},
		{"ss-style zone without port", "[fe80::1]%eth0", "fe80::1", "eth0", "", false},
		{"port only", ":http", "", "", "http", false},
		{"zone and port, no ip", "%eth0:80", "", "eth0", "80", false},
		{"zone only", "%eth0", "", "eth0", "", false},
		{"unbalanced bracket, with port", "fe80::1]:80", "fe80::1", "", "80", true},
		{"unbalanced bracket, no port", "fe80::1%eth0]", "fe80::1", "eth0", "", true},
		{"empty string is valid", "", "", "", "", false},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ip, zone, port, err := splitHostPort(tc.hostport)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.ip, ip)
			assert.Equal(t, tc.zone, zone)
			assert.Equal(t, tc.port, port)
		})
	}
}

func TestProtoVersionCheck(t *testing.T) {
	tests := []struct {
		name    string
		ver     protocolVersion
		wantErr bool
	}{
		{"v6 is valid", protocolV6, false},
		{"v4 is valid", protocolV4, false},
		{"zero is invalid", protocolVersion(0), true},
		{"five is invalid", protocolVersion(5), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protoVersionCheck(tc.ver)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestParsePlugins(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		got, err := parsePlugins([]any{})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("item that fails to cast at all still yields a non-nil empty map, rejected on count", func(t *testing.T) {
		// cast.ToStringMap falls back to an empty, non-nil map for a scalar
		// input, so this hits "exactly one plugin" rather than "not a string map".
		_, err := parsePlugins([]any{42})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one plugin")
	})

	t.Run("item is a typed-nil map hits the not-a-string-map branch", func(t *testing.T) {
		// cast.ToStringMap only returns nil for a typed map[string]any(nil);
		// YAML can't produce that, so this branch needs a direct call rather than a real config.
		_, err := parsePlugins([]any{map[string]any(nil)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a string map")
	})

	t.Run("multiple keys rejected", func(t *testing.T) {
		_, err := parsePlugins([]any{
			map[string]any{"foo": "a", "bar": "b"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one plugin")
	})

	t.Run("empty map rejected", func(t *testing.T) {
		_, err := parsePlugins([]any{map[string]any{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one plugin")
	})

	t.Run("single plugin with string args", func(t *testing.T) {
		got, err := parsePlugins([]any{
			map[string]any{"dns": "8.8.8.8 8.8.4.4"},
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "dns", got[0].Name)
		assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, got[0].Args)
	})

	t.Run("single plugin with a non-string args value", func(t *testing.T) {
		got, err := parsePlugins([]any{
			map[string]any{"lease_time": 3600},
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "lease_time", got[0].Name)
		assert.Equal(t, []string{"3600"}, got[0].Args)
	})

	t.Run("single plugin with no args", func(t *testing.T) {
		got, err := parsePlugins([]any{
			map[string]any{"server_id": nil},
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Empty(t, got[0].Args)
	})

	t.Run("multiple plugins preserve order", func(t *testing.T) {
		got, err := parsePlugins([]any{
			map[string]any{"a": "1"},
			map[string]any{"b": "2"},
		})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "a", got[0].Name)
		assert.Equal(t, "b", got[1].Name)
	})
}

func TestConfigGetListenAddress(t *testing.T) {
	c := New()

	tests := []struct {
		name     string
		addr     string
		ver      protocolVersion
		wantErr  string // substring; empty means success expected
		wantIP   net.IP
		wantPort int
		wantZone string
	}{
		{
			name:    "invalid protocol version",
			addr:    "0.0.0.0:67",
			ver:     protocolVersion(9),
			wantErr: "invalid protocol version",
		},
		{
			name:    "unparsable hostport",
			addr:    "0.0.0.0:20%eth0:67",
			ver:     protocolV4,
			wantErr: "dhcpv4:",
		},
		{
			name:     "v4 empty ip defaults to zero address and default port",
			addr:     "",
			ver:      protocolV4,
			wantIP:   net.IPv4zero,
			wantPort: dhcpv4.ServerPort,
		},
		{
			name:     "v6 empty ip defaults to unspecified address and default port",
			addr:     "",
			ver:      protocolV6,
			wantIP:   net.IPv6unspecified,
			wantPort: dhcpv6.DefaultServerPort,
		},
		{
			name:    "invalid ip literal",
			addr:    "not-an-ip:67",
			ver:     protocolV4,
			wantErr: "invalid IP address",
		},
		{
			name:    "ipv4 literal rejected for v6",
			addr:    "192.0.2.1:547",
			ver:     protocolV6,
			wantErr: "not a valid IPv6",
		},
		{
			name:    "ipv6 literal rejected for v4",
			addr:    "[fe80::1]:67",
			ver:     protocolV4,
			wantErr: "not a valid IPv4",
		},
		{
			name:     "explicit v4 port",
			addr:     "0.0.0.0:6767",
			ver:      protocolV4,
			wantIP:   net.IPv4zero,
			wantPort: 6767,
		},
		{
			name:    "invalid port",
			addr:    "0.0.0.0:notaport",
			ver:     protocolV4,
			wantErr: "invalid `listen` port",
		},
		{
			name:     "zoned v6 address",
			addr:     "[fe80::1%eth0]:547",
			ver:      protocolV6,
			wantIP:   net.ParseIP("fe80::1"),
			wantPort: 547,
			wantZone: "eth0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.getListenAddress(tc.addr, tc.ver)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, tc.wantIP.Equal(got.IP), "IP: got %v want %v", got.IP, tc.wantIP)
			assert.Equal(t, tc.wantPort, got.Port)
			assert.Equal(t, tc.wantZone, got.Zone)
		})
	}
}

func TestConfigGetPlugins(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		c := New()
		_, err := c.getPlugins(protocolVersion(9))
		require.Error(t, err)
	})

	t.Run("missing plugins section", func(t *testing.T) {
		c := New()
		_, err := c.getPlugins(protocolV6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid plugins section")
	})

	t.Run("plugins section not a list", func(t *testing.T) {
		c := New()
		c.v.Set("server6.plugins", "not-a-list")
		_, err := c.getPlugins(protocolV6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid plugins section")
	})

	t.Run("valid plugins list", func(t *testing.T) {
		c := New()
		c.v.Set("server4.plugins", []any{
			map[string]any{"router": "192.0.2.1"},
		})
		got, err := c.getPlugins(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "router", got[0].Name)
	})
}

func TestConfigParseConfig(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		c := New()
		err := c.parseConfig(protocolVersion(9))
		require.Error(t, err)
	})

	t.Run("no server section is valid, leaves the server config nil", func(t *testing.T) {
		c := New()
		err := c.parseConfig(protocolV6)
		require.NoError(t, err)
		assert.Nil(t, c.Server6)
	})

	t.Run("plugin error propagates", func(t *testing.T) {
		c := New()
		c.v.Set("server6", map[string]any{})
		err := c.parseConfig(protocolV6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid plugins section")
	})

	t.Run("listen error propagates", func(t *testing.T) {
		c := New()
		// Must be non-empty: an explicitly empty []any{} collapses to a nil
		// slice under cast.ToSliceE, which getPlugins would reject first.
		c.v.Set("server6.plugins", []any{
			map[string]any{"dns": "8.8.8.8"},
		})
		c.v.Set("server6.listen", []any{"not-an-ip"})
		err := c.parseConfig(protocolV6)
		require.Error(t, err)
	})

	t.Run("v6 success populates Server6 only", func(t *testing.T) {
		c := New()
		c.v.Set("server6.plugins", []any{
			map[string]any{"dns": "8.8.8.8"},
		})
		c.v.Set("server6.listen", []any{"[::1]:547"})
		err := c.parseConfig(protocolV6)
		require.NoError(t, err)
		require.NotNil(t, c.Server6)
		assert.Nil(t, c.Server4)
		assert.Len(t, c.Server6.Plugins, 1)
		assert.Len(t, c.Server6.Addresses, 1)
	})

	t.Run("v4 success populates Server4 only", func(t *testing.T) {
		c := New()
		c.v.Set("server4.plugins", []any{
			map[string]any{"router": "192.0.2.1"},
		})
		c.v.Set("server4.listen", []any{"127.0.0.1:6767"})
		err := c.parseConfig(protocolV4)
		require.NoError(t, err)
		require.NotNil(t, c.Server4)
		assert.Nil(t, c.Server6)
	})
}

// Exists because net.Interfaces can't be mocked without changing config.go; tests
// compute their expectation from actual host state instead of hard-coding an outcome.
func qualifyingInterfaces(t *testing.T, want net.Flags) []string {
	t.Helper()
	ifs, err := net.Interfaces()
	require.NoError(t, err)
	var names []string
	for _, iface := range ifs {
		if iface.Flags&want == want {
			names = append(names, iface.Name)
		}
	}
	return names
}

func TestExpandLLMulticast(t *testing.T) {
	t.Run("not multicast", func(t *testing.T) {
		_, err := expandLLMulticast(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 67})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not multicast")
	})

	t.Run("already zoned", func(t *testing.T) {
		_, err := expandLLMulticast(&net.UDPAddr{
			IP:   net.ParseIP("ff02::1:2"),
			Port: 547,
			Zone: "eth0",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already zoned")
	})

	t.Run("v6 link-local multicast, unzoned", func(t *testing.T) {
		want := qualifyingInterfaces(t, net.FlagMulticast)
		got, err := expandLLMulticast(&net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547})
		if len(want) == 0 {
			// No interface here carries FlagMulticast (not even loopback): the
			// "no suitable interface" branch, otherwise unreachable without controlling the host.
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no suitable interface")
			return
		}
		require.NoError(t, err)
		assert.Len(t, got, len(want))
		for _, l := range got {
			assert.Contains(t, want, l.Zone)
			assert.Equal(t, 547, l.Port)
		}
	})

	t.Run("v4 link-local multicast, unzoned", func(t *testing.T) {
		want := qualifyingInterfaces(t, net.FlagMulticast|net.FlagBroadcast)
		got, err := expandLLMulticast(&net.UDPAddr{IP: net.ParseIP("224.0.0.1"), Port: 67})
		if len(want) == 0 {
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no suitable interface")
			return
		}
		require.NoError(t, err)
		assert.Len(t, got, len(want))
		for _, l := range got {
			assert.Contains(t, want, l.Zone)
			assert.Equal(t, 67, l.Port)
		}
	})
}

func TestDefaultListen(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		_, err := defaultListen(protocolVersion(9))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Incorrect protocol version")
	})

	t.Run("v4", func(t *testing.T) {
		got, err := defaultListen(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, dhcpv4.ServerPort, got[0].Port)
	})

	t.Run("v6", func(t *testing.T) {
		// Depends on at least one interface carrying FlagMulticast so
		// expandLLMulticast succeeds; loopback has, on every environment this has run on.
		got, err := defaultListen(protocolV6)
		require.NoError(t, err)
		require.NotEmpty(t, got)
		last := got[len(got)-1]
		assert.True(t, dhcpv6.AllDHCPServers.Equal(last.IP))
		assert.Equal(t, dhcpv6.DefaultServerPort, last.Port)
	})
}

func TestConfigParseListen(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		c := New()
		_, err := c.parseListen(protocolVersion(9))
		require.Error(t, err)
	})

	t.Run("listen and deprecated interface both set is an error", func(t *testing.T) {
		c := New()
		c.v.Set("server6.listen", "[::1]:547")
		c.v.Set("server6.interface", "eth0")
		_, err := c.parseListen(protocolV6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deprecated alias")
	})

	t.Run("deprecated interface alias without listen", func(t *testing.T) {
		c := New()
		c.v.Set("server4.interface", "lo0")
		got, err := c.parseListen(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "lo0", got[0].Zone)
	})

	t.Run("neither listen nor interface set falls back to defaults", func(t *testing.T) {
		c := New()
		got, err := c.parseListen(protocolV4)
		require.NoError(t, err)
		want, err := defaultListen(protocolV4)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("listen as a real list", func(t *testing.T) {
		c := New()
		c.v.Set("server4.listen", []any{"127.0.0.1:6767", "127.0.0.2:6768"})
		got, err := c.parseListen(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("listen as a plain string goes through ToStringSliceE's string case", func(t *testing.T) {
		c := New()
		c.v.Set("server4.listen", "127.0.0.1:6767")
		got, err := c.parseListen(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 1)
	})

	t.Run("listen value that ToStringSliceE cannot cast falls back to cast.ToString", func(t *testing.T) {
		c := New()
		// A map has no ToStringSliceE or ToStringE case, so parseListen falls
		// through to cast.ToString, which yields "" - the trivial empty address.
		c.v.Set("server4.listen", map[string]any{"a": "b"})
		got, err := c.parseListen(protocolV4)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.True(t, net.IPv4zero.Equal(got[0].IP))
	})

	t.Run("bad address in list propagates the error", func(t *testing.T) {
		c := New()
		c.v.Set("server4.listen", []any{"not-an-ip"})
		_, err := c.parseListen(protocolV4)
		require.Error(t, err)
	})

	t.Run("unzoned multicast expands to all qualifying interfaces", func(t *testing.T) {
		c := New()
		want := qualifyingInterfaces(t, net.FlagMulticast)
		c.v.Set("server6.listen", []any{"[ff02::1:2]:547"})
		got, err := c.parseListen(protocolV6)
		if len(want) == 0 {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Len(t, got, len(want))
	})

	t.Run("zoned multicast is not expanded", func(t *testing.T) {
		c := New()
		c.v.Set("server6.listen", []any{"[ff02::1:2%lo0]:547"})
		got, err := c.parseListen(protocolV6)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "lo0", got[0].Zone)
	})
}

func TestDefaultIPUnknownVersionPanics(t *testing.T) {
	assert.PanicsWithValue(t, "BUG: Unknown protocol version", func() {
		defaultIP(protocolVersion(9))
	})
}

func TestDefaultPortUnknownVersionPanics(t *testing.T) {
	assert.PanicsWithValue(t, "BUG: Unknown protocol version", func() {
		defaultPort(protocolVersion(9))
	})
}

func withNetInterfaces(t *testing.T, fn func() ([]net.Interface, error)) {
	t.Helper()
	orig := netInterfaces
	netInterfaces = fn
	t.Cleanup(func() { netInterfaces = orig })
}

func TestExpandLLMulticastInterfaceListError(t *testing.T) {
	withNetInterfaces(t, func() ([]net.Interface, error) {
		return nil, errors.New("enumeration failed")
	})
	_, err := expandLLMulticast(&net.UDPAddr{IP: net.ParseIP("ff02::1:2")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not list network interfaces")
}

func TestExpandLLMulticastNoSuitableInterface(t *testing.T) {
	withNetInterfaces(t, func() ([]net.Interface, error) {
		// Loopback only: no multicast flag, so nothing qualifies.
		return []net.Interface{{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}}, nil
	})
	_, err := expandLLMulticast(&net.UDPAddr{IP: net.ParseIP("ff02::1:2")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no suitable interface found")
}

func TestDefaultListenV6PropagatesInterfaceError(t *testing.T) {
	withNetInterfaces(t, func() ([]net.Interface, error) {
		return nil, errors.New("enumeration failed")
	})
	_, err := defaultListen(protocolV6)
	require.Error(t, err)
}

func TestParseListenPropagatesMulticastExpansionError(t *testing.T) {
	withNetInterfaces(t, func() ([]net.Interface, error) {
		return nil, errors.New("enumeration failed")
	})
	c := &Config{v: viper.New()}
	c.v.Set("server6.listen", []string{"[ff02::1:2]"})
	_, err := c.parseListen(protocolV6)
	require.Error(t, err)
}
