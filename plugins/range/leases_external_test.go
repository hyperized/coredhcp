// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin_test

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	rangeplugin "github.com/coredhcp/coredhcp/plugins/range"
)

// registeredSource unregisters itself via cleanup so later tests don't see
// stale global registry state.
func registeredSource(t *testing.T, name string) leases.Source {
	t.Helper()
	for _, s := range leases.Sources() {
		if s.Name() == name {
			t.Cleanup(func() { leases.Unregister(s) })
			return s
		}
	}
	t.Fatalf("no source registered as %q", name)
	return nil
}

func TestLeasesFollowTheHandler(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	h4, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.9.1", "10.0.9.4", "1h")
	require.NoError(t, err)
	src := registeredSource(t, "range "+dbPath)

	assert.Empty(t, src.Leases())
	assert.Equal(t, []leases.Pool{{
		Source: "range " + dbPath,
		Family: 4,
		Range:  "10.0.9.1-10.0.9.4",
		Size:   4,
	}}, src.Pools())

	hwaddr, err := net.ParseMAC("02:00:00:00:09:01")
	require.NoError(t, err)
	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	req.UpdateOption(dhcpv4.OptHostName("laptop"))
	resp, stop := h4(req, &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)})
	require.NotNil(t, resp)
	require.False(t, stop)

	held := src.Leases()
	require.Len(t, held, 1)
	assert.Equal(t, uint8(4), held[0].Family)
	assert.Equal(t, "02:00:00:00:09:01", held[0].Client)
	assert.Equal(t, netip.MustParsePrefix("10.0.9.1/32"), held[0].Address)
	assert.Equal(t, "laptop", held[0].Hostname)
	assert.False(t, held[0].Static)
	assert.False(t, held[0].Expires.IsZero())
	assert.Equal(t, "range "+dbPath, held[0].Source)

	assert.Equal(t, 1, src.Pools()[0].Used)
}

func TestDeclinedAddressesAreReportedAsQuarantined(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	h4, err := rangeplugin.Plugin.Setup4(dbPath, "10.0.10.1", "10.0.10.4", "1h")
	require.NoError(t, err)
	src := registeredSource(t, "range "+dbPath)

	hwaddr, err := net.ParseMAC("02:00:00:00:0a:01")
	require.NoError(t, err)
	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp, _ := h4(req, &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)})
	require.NotNil(t, resp)

	decline := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr, Options: make(dhcpv4.Options)}
	decline.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	decline.UpdateOption(dhcpv4.OptRequestedIPAddress(resp.YourIPAddr))
	_, _ = h4(decline, &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)})

	// Declined addresses sit in probation: nobody's lease, but not free
	// either, so a leases-only report would wrongly show it as available.
	assert.Empty(t, src.Leases())
	pool := src.Pools()[0]
	assert.Equal(t, 0, pool.Used)
	assert.Equal(t, 1, pool.Quarantined)
	assert.Equal(t, 4, pool.Size)
}
