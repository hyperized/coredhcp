// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6_test

import (
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/plugins/range6"
)

// registeredSource finds the source setup registered and unregisters it on cleanup.
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
	dbPath := filepath.Join(t.TempDir(), "leases6.db")
	h6, err := range6.Plugin.Setup6(dbPath, poolFirst, poolLast, leaseTime)
	require.NoError(t, err)
	src := registeredSource(t, "range6 "+dbPath)

	assert.Empty(t, src.Leases())
	assert.Equal(t, []leases.Pool{{
		Source: "range6 " + dbPath,
		Family: 6,
		Range:  poolFirst + "-" + poolLast,
		Size:   256,
	}}, src.Pools())

	duid := testDUID(1)
	held := solicit(t, h6, duid, iaid1)

	holdLeases := src.Leases()
	require.Len(t, holdLeases, 1)
	assert.Equal(t, uint8(6), holdLeases[0].Family)
	assert.Equal(t, hex.EncodeToString(duidBytes(t, duid)), holdLeases[0].Client)
	assert.Equal(t, uint32(1), holdLeases[0].IAID)
	assert.Equal(t, netip.MustParsePrefix(held.String()+"/128"), holdLeases[0].Address)
	assert.False(t, holdLeases[0].Static)
	assert.False(t, holdLeases[0].Expires.IsZero())
	assert.Equal(t, "range6 "+dbPath, holdLeases[0].Source)

	assert.Equal(t, 1, src.Pools()[0].Used)
}

func TestDeclinedAddressesAreReportedAsQuarantined(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.db")
	h6, err := range6.Plugin.Setup6(dbPath, poolFirst, poolLast, leaseTime)
	require.NoError(t, err)
	src := registeredSource(t, "range6 "+dbPath)

	duid := testDUID(1)
	held := solicit(t, h6, duid, iaid1)

	resp, _ := exchange(t, h6, newRequest(t, dhcpv6.MessageTypeDecline, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)

	// Declined: not bound, not free; it must show as quarantined.
	assert.Empty(t, src.Leases())
	pool := src.Pools()[0]
	assert.Equal(t, 0, pool.Used)
	assert.Equal(t, 1, pool.Quarantined)
	assert.Equal(t, 256, pool.Size)
}

// duidBytes is the DUID in the plugin's internal key form.
func duidBytes(t *testing.T, duid dhcpv6.DUID) []byte {
	t.Helper()
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	return req.Options.ClientID().ToBytes()
}
