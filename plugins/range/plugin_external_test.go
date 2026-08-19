// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin_test

import (
	"database/sql"
	"net"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// The "sqlite" driver is registered by rangeplugin's own storage.go
	// import, which is already pulled in below.
	rangeplugin "github.com/coredhcp/coredhcp/plugins/range"
)

// seedDB creates the leases4 table (matching what storage.go creates) and
// inserts rows directly with SQL, bypassing any of the plugin's own
// validation, to set up scenarios setupRange must handle when reloading
// leases from a pre-existing database.
func seedDB(t *testing.T, path string, rows [][4]any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	_, err = db.Exec("create table if not exists leases4 (mac string not null, ip string not null, expiry int, hostname string not null, primary key (mac, ip))")
	require.NoError(t, err)
	for _, r := range rows {
		_, err := db.Exec("insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)", r[0], r[1], r[2], r[3])
		require.NoError(t, err)
	}
}

func TestPluginSetupArgValidation(t *testing.T) {
	cases := []struct {
		name string
		args func(t *testing.T) []string
	}{
		{"too few arguments", func(*testing.T) []string {
			return []string{"unused.db", "10.0.0.1", "10.0.0.10"}
		}},
		{"empty file name", func(*testing.T) []string {
			return []string{"", "10.0.0.1", "10.0.0.10", "1h"}
		}},
		{"invalid start IP", func(*testing.T) []string {
			return []string{"unused.db", "not-an-ip", "10.0.0.10", "1h"}
		}},
		{"invalid end IP", func(*testing.T) []string {
			return []string{"unused.db", "10.0.0.1", "not-an-ip", "1h"}
		}},
		{"inverted range", func(*testing.T) []string {
			return []string{"unused.db", "10.0.0.10", "10.0.0.1", "1h"}
		}},
		{"invalid lease duration", func(*testing.T) []string {
			return []string{"unused.db", "10.0.0.1", "10.0.0.10", "not-a-duration"}
		}},
		{"unwritable db path", func(t *testing.T) []string {
			t.Helper()
			return []string{filepath.Join(t.TempDir(), "nonexistent", "leases.db"), "10.0.0.1", "10.0.0.10", "1h"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rangeplugin.Plugin.Setup4(tc.args(t)...)
			assert.Error(t, err)
		})
	}
}

func TestPluginSetupAndHandler4NewAllocationThenRenewal(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	h4, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.0.1", "10.0.0.5", "1h")
	require.NoError(t, err)
	require.NotNil(t, h4)

	hwaddr, err := net.ParseMAC("02:00:00:00:01:00")
	require.NoError(t, err)
	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	result, stop := h4(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.NotNil(t, result.YourIPAddr)

	// Renewal: the same MAC asking again must get the same address back.
	resp2 := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}
	result2, stop2 := h4(req, resp2)
	require.NotNil(t, result2)
	assert.False(t, stop2)
	assert.Equal(t, result.YourIPAddr, result2.YourIPAddr)
}

func TestPluginSetupReloadsExistingLeases(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	seedDB(t, dbPath, [][4]any{{"02:00:00:00:02:00", "10.0.1.1", 1, "h"}})

	h4, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.1.1", "10.0.1.2", "1h")
	require.NoError(t, err)

	// The first address was already re-allocated to the record loaded from
	// storage, so a new client must get the second one.
	hwaddr, err := net.ParseMAC("02:00:00:00:02:01")
	require.NoError(t, err)
	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}
	result, _ := h4(req, resp)
	require.NotNil(t, result)
	assert.Equal(t, net.IPv4(10, 0, 1, 2).To4(), result.YourIPAddr)
}

func TestPluginSetupLoadRecordsFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	seedDB(t, dbPath, [][4]any{{"not-a-mac", "10.0.0.1", 1, "h"}})

	_, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.0.1", "10.0.0.5", "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not load records from file")
}

func TestPluginSetupReallocationExhausted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	// Two different MACs sharing the same IP, but the range only has room
	// for one address: re-allocating the second record must fail with "no
	// address available".
	seedDB(t, dbPath, [][4]any{
		{"02:00:00:00:03:00", "10.0.2.1", 1, "a"},
		{"02:00:00:00:03:01", "10.0.2.1", 1, "b"},
	})

	_, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.2.1", "10.0.2.1", "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to re-allocate leased ip")
}

func TestPluginSetupReallocationMismatch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	// Two different MACs sharing the same IP, with a second address free in
	// the range: the allocator falls back to it instead of the requested
	// hint, which setupRange treats as a reallocation mismatch.
	seedDB(t, dbPath, [][4]any{
		{"02:00:00:00:04:00", "10.0.3.1", 1, "a"},
		{"02:00:00:00:04:01", "10.0.3.1", 1, "b"},
	})

	_, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.3.1", "10.0.3.2", "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not re-allocate requested leased ip")
}

// TestPluginSetupSweepArgument covers the optional fifth argument end to end.
// Anything that is not a sweep argument is rejected rather than silently
// ignored, so a typo in the config surfaces at startup.
func TestPluginSetupSweepArgument(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   []string
		wantErr bool
	}{
		{name: "omitted", extra: nil},
		{name: "explicit interval", extra: []string{"sweep:90s"}},
		{name: "bare duration", extra: []string{"90s"}, wantErr: true},
		{name: "malformed duration", extra: []string{"sweep:soon"}, wantErr: true},
		{name: "zero interval", extra: []string{"sweep:0s"}, wantErr: true},
		{name: "negative interval", extra: []string{"sweep:-1m"}, wantErr: true},
		{name: "two sweep arguments", extra: []string{"sweep:90s", "sweep:2m"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{filepath.Join(t.TempDir(), "leases.db"), "10.0.0.1", "10.0.0.5", "1h"}, tc.extra...)
			h4, err := rangeplugin.Plugin.Setup4(args...)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, h4)
		})
	}
}
