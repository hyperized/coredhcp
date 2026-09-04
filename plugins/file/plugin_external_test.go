// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file_test

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/file"
)

func writeLeases(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leases.txt")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoadDHCPv4Records(t *testing.T) {
	cases := []struct {
		name      string
		contents  string
		wantErr   bool
		wantCount int
	}{
		{
			name: "valid leases with mixed case and trailing comment",
			contents: "00:11:22:33:44:aa 192.0.2.100\n" +
				" 11:BB:33:DD:55:FF \t 192.0.2.101  # arbitrary spaces and trailing comment\n" +
				" # this is a simple comment\n",
			wantCount: 2,
		},
		{name: "missing field", contents: "foo\n", wantErr: true},
		{name: "invalid MAC address", contents: "abcd 192.0.2.102\n", wantErr: true},
		{name: "invalid IP address", contents: "22:33:44:55:66:77 bcde\n", wantErr: true},
		{
			// The MAC is the map key, so the second line overwrites the
			// first rather than producing two entries.
			name:      "duplicate MAC address is allowed",
			contents:  "aa:11:11:11:11:11 1.2.3.4\nAA:11:11:11:11:11 5.6.7.8\n",
			wantCount: 1,
		},
		{
			name:      "duplicate IP address is allowed",
			contents:  "11:11:11:11:11:11 1.2.3.4\n22:22:22:22:22:22 1.2.3.4\n33:33:33:33:33:33 1.2.3.4\n",
			wantCount: 3,
		},
		{name: "IPv6 address instead of IPv4", contents: "00:11:22:33:44:55 2001:db8::10:1\n", wantErr: true},
		{
			name:     "line exceeding the scanner buffer",
			contents: "00:11:22:33:44:55 " + strings.Repeat("a", 70000) + "\n",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeLeases(t, tc.contents)
			records, err := file.LoadDHCPv4Records(path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, records, tc.wantCount)
		})
	}

	t.Run("valid record values", func(t *testing.T) {
		path := writeLeases(t, "00:11:22:33:44:aa 192.0.2.100\n11:bb:33:dd:55:ff 192.0.2.101\n")
		records, err := file.LoadDHCPv4Records(path)
		require.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("192.0.2.100"), records["00:11:22:33:44:aa"])
		assert.Equal(t, netip.MustParseAddr("192.0.2.101"), records["11:bb:33:dd:55:ff"])
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := file.LoadDHCPv4Records(filepath.Join(t.TempDir(), "missing.txt"))
		assert.Error(t, err)
	})
}

func TestLoadDHCPv6Records(t *testing.T) {
	cases := []struct {
		name      string
		contents  string
		wantErr   bool
		wantCount int
	}{
		{
			name: "valid leases with trailing comment",
			contents: "00:11:22:33:44:aa 2001:db8::10:1\n" +
				" 11:BB:33:DD:55:FF \t 2001:db8::10:2  # arbitrary spaces and trailing comment\n" +
				" # this is a simple comment\n",
			wantCount: 2,
		},
		{name: "missing field", contents: "foo\n", wantErr: true},
		{name: "invalid MAC address", contents: "abcd 2001:db8::10:3\n", wantErr: true},
		{name: "invalid IP address", contents: "22:33:44:55:66:77 bcde\n", wantErr: true},
		{
			// The MAC is the map key, so the second line overwrites the
			// first rather than producing two entries.
			name:      "duplicate MAC address is allowed",
			contents:  "aa:11:11:11:11:11 2001:db8::10:1\nAA:11:11:11:11:11 2001:db8::10:2\n",
			wantCount: 1,
		},
		{
			name:      "duplicate IP address is allowed",
			contents:  "11:11:11:11:11:11 2001:db8::10:1\n22:22:22:22:22:22 2001:db8::10:1\n33:33:33:33:33:33 2001:db8::10:1\n",
			wantCount: 3,
		},
		{name: "IPv4 address instead of IPv6", contents: "00:11:22:33:44:55 192.0.2.100\n", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeLeases(t, tc.contents)
			records, err := file.LoadDHCPv6Records(path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, records, tc.wantCount)
		})
	}

	t.Run("valid record values", func(t *testing.T) {
		path := writeLeases(t, "00:11:22:33:44:aa 2001:db8::10:1\n11:bb:33:dd:55:ff 2001:db8::10:2\n")
		records, err := file.LoadDHCPv6Records(path)
		require.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("2001:db8::10:1"), records["00:11:22:33:44:aa"])
		assert.Equal(t, netip.MustParseAddr("2001:db8::10:2"), records["11:bb:33:dd:55:ff"])
	})
}

func TestPluginSetupArgValidation(t *testing.T) {
	for _, setup := range []struct {
		name string
		fn   func(args ...string) error
	}{
		{"Setup4", func(args ...string) error { _, err := file.Plugin.Setup4(args...); return err }},
		{"Setup6", func(args ...string) error { _, err := file.Plugin.Setup6(args...); return err }},
	} {
		t.Run(setup.name, func(t *testing.T) {
			t.Run("no arguments", func(t *testing.T) {
				assert.Error(t, setup.fn())
			})
			t.Run("empty file name", func(t *testing.T) {
				assert.Error(t, setup.fn(""))
			})
			t.Run("nonexistent file", func(t *testing.T) {
				assert.Error(t, setup.fn(filepath.Join(t.TempDir(), "missing.txt")))
			})
		})
	}
}

func TestPluginSetupTypicalCase(t *testing.T) {
	path := writeLeases(t, "aa:11:22:33:44:55 2001:db8::10:1\n11:22:33:44:55:66 2001:db8::10:2\n")

	h6, err := file.Plugin.Setup6(path)
	require.NoError(t, err)
	assert.NotNil(t, h6)
}

func TestHandler4(t *testing.T) {
	knownMAC := "aa:11:22:33:44:55"
	path := writeLeases(t, knownMAC+" 192.0.2.100\n")
	h4, err := file.Plugin.Setup4(path)
	require.NoError(t, err)

	t.Run("unknown MAC", func(t *testing.T) {
		claddr, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
		req := &dhcpv4.DHCPv4{ClientHWAddr: claddr}
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Same(t, resp, result)
		assert.False(t, stop)
		assert.Nil(t, result.YourIPAddr)
	})

	t.Run("known MAC", func(t *testing.T) {
		claddr, _ := net.ParseMAC(knownMAC)
		req := &dhcpv4.DHCPv4{ClientHWAddr: claddr}
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Same(t, resp, result)
		assert.True(t, stop)
		assert.Equal(t, net.IP(netip.MustParseAddr("192.0.2.100").AsSlice()), result.YourIPAddr)
	})

	t.Run("INFORM passes through untouched", func(t *testing.T) {
		claddr, _ := net.ParseMAC(knownMAC)
		req := &dhcpv4.DHCPv4{ClientHWAddr: claddr}
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
		resp := &dhcpv4.DHCPv4{}

		result, stop := h4(req, resp)
		assert.Same(t, resp, result)
		assert.False(t, stop)
		assert.Nil(t, result.YourIPAddr)
	})

	// A static reservation has nothing to free, so RELEASE and DECLINE from a
	// known MAC must pass through untouched rather than getting the reserved
	// address stamped in and the chain cut short.
	releaseDeclineCases := []struct {
		name string
		mt   dhcpv4.MessageType
	}{
		{"RELEASE passes through untouched", dhcpv4.MessageTypeRelease},
		{"DECLINE passes through untouched", dhcpv4.MessageTypeDecline},
	}
	for _, tc := range releaseDeclineCases {
		t.Run(tc.name, func(t *testing.T) {
			claddr, _ := net.ParseMAC(knownMAC)
			req := &dhcpv4.DHCPv4{ClientHWAddr: claddr}
			req.UpdateOption(dhcpv4.OptMessageType(tc.mt))
			resp := &dhcpv4.DHCPv4{}

			result, stop := h4(req, resp)
			assert.Same(t, resp, result)
			assert.False(t, stop)
			assert.Nil(t, result.YourIPAddr)
		})
	}

	// Guard against the RELEASE/DECLINE check swallowing message types that
	// must still get the reserved address.
	regularCases := []struct {
		name string
		mt   dhcpv4.MessageType
	}{
		{"DISCOVER from a known MAC still gets the address", dhcpv4.MessageTypeDiscover},
		{"REQUEST from a known MAC still gets the address", dhcpv4.MessageTypeRequest},
	}
	for _, tc := range regularCases {
		t.Run(tc.name, func(t *testing.T) {
			claddr, _ := net.ParseMAC(knownMAC)
			req := &dhcpv4.DHCPv4{ClientHWAddr: claddr}
			req.UpdateOption(dhcpv4.OptMessageType(tc.mt))
			resp := &dhcpv4.DHCPv4{}

			result, stop := h4(req, resp)
			assert.Same(t, resp, result)
			assert.True(t, stop)
			assert.Equal(t, net.IP(netip.MustParseAddr("192.0.2.100").AsSlice()), result.YourIPAddr)
		})
	}
}

func TestHandler6(t *testing.T) {
	knownMAC := "aa:11:22:33:44:55"
	path := writeLeases(t, knownMAC+" 2001:db8::10:1\n")
	h6, err := file.Plugin.Setup6(path)
	require.NoError(t, err)

	t.Run("unknown MAC", func(t *testing.T) {
		claddr, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
		req, err := dhcpv6.NewSolicit(claddr)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.False(t, stop)
		assert.Equal(t, 0, len(result.GetOption(dhcpv6.OptionIANA)))
	})

	t.Run("known MAC", func(t *testing.T) {
		claddr, _ := net.ParseMAC(knownMAC)
		req, err := dhcpv6.NewSolicit(claddr)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.False(t, stop)
		if assert.Equal(t, 1, len(result.GetOption(dhcpv6.OptionIANA))) {
			opt := result.GetOneOption(dhcpv6.OptionIANA)
			assert.Contains(t, opt.String(), "IP=2001:db8::10:1")
		}
	})

	// A Reply to a Release or Decline must not hand the address back to the
	// client, even for a MAC with a known reservation.
	noIANACases := []struct {
		name string
		mt   dhcpv6.MessageType
	}{
		{"Release does not add an IA_NA", dhcpv6.MessageTypeRelease},
		{"Decline does not add an IA_NA", dhcpv6.MessageTypeDecline},
	}
	for _, tc := range noIANACases {
		t.Run(tc.name, func(t *testing.T) {
			claddr, _ := net.ParseMAC(knownMAC)
			req, err := dhcpv6.NewSolicit(claddr)
			require.NoError(t, err)
			req.MessageType = tc.mt
			resp, err := dhcpv6.NewMessage()
			require.NoError(t, err)

			result, stop := h6(req, resp)
			assert.Same(t, resp, result)
			assert.False(t, stop)
			assert.Equal(t, 0, len(result.GetOption(dhcpv6.OptionIANA)))
		})
	}

	// Guard against the Release/Decline check swallowing message types that
	// must still get their IA_NA.
	t.Run("Request from a known MAC still gets its IA_NA", func(t *testing.T) {
		claddr, _ := net.ParseMAC(knownMAC)
		req, err := dhcpv6.NewSolicit(claddr)
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.False(t, stop)
		if assert.Equal(t, 1, len(result.GetOption(dhcpv6.OptionIANA))) {
			opt := result.GetOneOption(dhcpv6.OptionIANA)
			assert.Contains(t, opt.String(), "IP=2001:db8::10:1")
		}
	})

	t.Run("cannot decapsulate", func(t *testing.T) {
		// A RelayMessage with no embedded relay-message option fails to
		// decapsulate.
		req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("no address requested", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.Same(t, resp, result)
		assert.False(t, stop)
	})

	t.Run("cannot extract MAC", func(t *testing.T) {
		// An IA_NA is present (so the OneIANA check passes) but there is no
		// client ID option to derive a MAC from.
		req, err := dhcpv6.NewMessage(dhcpv6.WithIANA())
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		result, stop := h6(req, resp)
		assert.Same(t, resp, result)
		assert.False(t, stop)
		assert.Equal(t, 0, len(result.GetOption(dhcpv6.OptionIANA)))
	})
}

// TestAutorefresh exercises the full autorefresh lifecycle: the initial load,
// picking up a valid update, surviving a malformed update without losing the
// previously loaded leases, and recovering once a valid file is written
// again. All waits use require.Eventually against directly observable state
// rather than fixed sleeps: handler responses, and the logged warning for
// the otherwise invisible failed-reload case.
func TestAutorefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.txt")
	mac1, mac2, mac3 := "aa:11:22:33:44:55", "aa:11:22:33:44:66", "aa:11:22:33:44:77"

	require.NoError(t, os.WriteFile(path, []byte(mac1+" 2001:db8::10:1\n"), 0o600))

	logPath := filepath.Join(dir, "plugin.log")
	require.NoError(t, logger.WithFile(logPath))
	t.Cleanup(func() { _ = logger.WithFile(os.DevNull) })

	h6, err := file.Plugin.Setup6(path, "autorefresh")
	require.NoError(t, err)

	resolves := func(mac string) func() bool {
		return func() bool {
			claddr, err := net.ParseMAC(mac)
			if err != nil {
				return false
			}
			req, err := dhcpv6.NewSolicit(claddr)
			if err != nil {
				return false
			}
			resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
			if err != nil {
				return false
			}
			result, _ := h6(req, resp)
			return len(result.GetOption(dhcpv6.OptionIANA)) == 1
		}
	}

	require.True(t, resolves(mac1)(), "initial lease must resolve right after setup")

	// A valid update should be picked up.
	require.NoError(t, os.WriteFile(path, []byte(mac1+" 2001:db8::10:1\n"+mac2+" 2001:db8::10:2\n"), 0o600))
	require.Eventually(t, resolves(mac2), 5*time.Second, 20*time.Millisecond,
		"autorefresh did not pick up the newly added record")

	// A malformed update must fail the reload (logging a warning) without
	// disturbing the previously loaded leases. It is written in place rather
	// than with os.WriteFile, which truncates first: the watcher can reload
	// between the truncate and the write, and an empty file is a valid file
	// with no leases, so the leases would already be gone before the bad
	// content ever landed.
	overwrite(t, path, "this is not a valid lease line\n")
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(logPath)
		if err != nil {
			return false
		}
		return strings.Contains(string(data), "failed to refresh from")
	}, 5*time.Second, 20*time.Millisecond, "expected a refresh-failure warning to be logged")
	assert.True(t, resolves(mac1)(), "previously loaded lease must keep resolving after a bad reload")
	assert.True(t, resolves(mac2)(), "previously loaded lease must keep resolving after a bad reload")

	// The watcher goroutine must still be running after the failed reload:
	// a further valid update should be picked up too.
	require.NoError(t, os.WriteFile(path, []byte(mac1+" 2001:db8::10:1\n"+mac3+" 2001:db8::10:3\n"), 0o600))
	require.Eventually(t, resolves(mac3), 5*time.Second, 20*time.Millisecond,
		"autorefresh did not recover after a bad reload")
}

// overwrite replaces the start of path with data without truncating it, so a
// watcher never sees the file empty. What was there before stays on after the
// new content, which is fine for content that is meant to be malformed.
func overwrite(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte(data), 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
