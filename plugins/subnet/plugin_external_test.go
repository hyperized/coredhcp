// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package subnet_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpiana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins/subnet"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "subnets.yml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestPluginMetadata(t *testing.T) {
	assert.Equal(t, "subnet", subnet.Plugin.Name)
	assert.Nil(t, subnet.Plugin.Setup4)
	assert.Nil(t, subnet.Plugin.Setup6)
}

func TestSetup4Ctx(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		_, err := subnet.Plugin.Setup4Ctx()
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		leasedb := filepath.Join(t.TempDir(), "leases.sqlite3")
		body := fmt.Sprintf("subnets:\n"+
			"  - name: main\n"+
			"    cidr: 10.0.0.0/24\n"+
			"    default: true\n"+
			"    pool: 10.0.0.100-10.0.0.200\n"+
			"    lease: 1h\n"+
			"    leasedb: %s\n", leasedb)
		path := writeYAML(t, body)

		h, err := subnet.Plugin.Setup4Ctx("file:" + path)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

func TestSetup6Ctx(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		_, err := subnet.Plugin.Setup6Ctx()
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		body := "subnets:\n" +
			"  - name: main\n" +
			"    cidr: 2001:db8::/48\n" +
			"    default: true\n" +
			"    prefixpool: 2001:db8::/48\n" +
			"    prefixsize: 64\n" +
			"    lease: 1h\n"
		path := writeYAML(t, body)

		h, err := subnet.Plugin.Setup6Ctx("file:" + path)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// withinRange asserts that ip falls inside [start, end], inclusive, treating
// all three as IPv4 addresses.
func withinRange(t *testing.T, ip net.IP, start, end string) {
	t.Helper()
	addr, ok := netip.AddrFromSlice(ip.To4())
	require.True(t, ok, "not a valid IPv4 address: %s", ip)
	lo := netip.MustParseAddr(start)
	hi := netip.MustParseAddr(end)
	assert.True(t, addr.Compare(lo) >= 0 && addr.Compare(hi) <= 0,
		"%s is not within %s-%s", ip, start, end)
}

// TestEndToEndDHCPv4TwoSubnets proves that each configured subnet gets its
// own range instance rather than sharing one: a request relayed through each
// subnet's gateway must be allocated from that subnet's own pool.
func TestEndToEndDHCPv4TwoSubnets(t *testing.T) {
	officeDB := filepath.Join(t.TempDir(), "office.sqlite3")
	guestDB := filepath.Join(t.TempDir(), "guest.sqlite3")
	body := fmt.Sprintf("subnets:\n"+
		"  - name: office\n"+
		"    cidr: 10.0.1.0/24\n"+
		"    match:\n"+
		"      relays: [10.0.1.1]\n"+
		"    pool: 10.0.1.100-10.0.1.200\n"+
		"    lease: 1h\n"+
		"    leasedb: %s\n"+
		"  - name: guest\n"+
		"    cidr: 10.0.2.0/24\n"+
		"    match:\n"+
		"      relays: [10.0.2.1]\n"+
		"    pool: 10.0.2.100-10.0.2.200\n"+
		"    lease: 1h\n"+
		"    leasedb: %s\n", officeDB, guestDB)
	path := writeYAML(t, body)

	h, err := subnet.Plugin.Setup4Ctx("file:" + path)
	require.NoError(t, err)

	officeMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	req1, err := dhcpv4.NewDiscovery(officeMAC)
	require.NoError(t, err)
	req1.GatewayIPAddr = net.ParseIP("10.0.1.1")
	resp1, err := dhcpv4.NewReplyFromRequest(req1)
	require.NoError(t, err)

	got1, stop1 := h(context.Background(), req1, resp1)
	assert.False(t, stop1)
	withinRange(t, got1.YourIPAddr, "10.0.1.100", "10.0.1.200")

	guestMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	req2, err := dhcpv4.NewDiscovery(guestMAC)
	require.NoError(t, err)
	req2.GatewayIPAddr = net.ParseIP("10.0.2.1")
	resp2, err := dhcpv4.NewReplyFromRequest(req2)
	require.NoError(t, err)

	got2, stop2 := h(context.Background(), req2, resp2)
	assert.False(t, stop2)
	withinRange(t, got2.YourIPAddr, "10.0.2.100", "10.0.2.200")
}

// TestEndToEndDHCPv6PrefixDelegation covers a subnet matched by interface
// that delegates to its own prefix pool and carries its configured resolver.
func TestEndToEndDHCPv6PrefixDelegation(t *testing.T) {
	body := "subnets:\n" +
		"  - name: v6\n" +
		"    cidr: 2001:db8:2::/48\n" +
		"    match:\n" +
		"      interfaces: [eth2]\n" +
		"    prefixpool: 2001:db8:2::/48\n" +
		"    prefixsize: 64\n" +
		"    lease: 1h\n" +
		"    options:\n" +
		"      dns: [2001:db8:2::53]\n"
	path := writeYAML(t, body)

	h, err := subnet.Plugin.Setup6Ctx("file:" + path)
	require.NoError(t, err)

	duid := &dhcpv6.DUIDLL{
		HWType:        dhcpiana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}))
	require.NoError(t, err)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{Interface: "eth2"})
	got, stop := h(ctx, req, resp)
	assert.False(t, stop)

	msg, ok := got.(*dhcpv6.Message)
	require.True(t, ok)

	iapds := msg.Options.IAPD()
	require.Len(t, iapds, 1)
	prefixes := iapds[0].Options.Prefixes()
	require.Len(t, prefixes, 1)

	length, _ := prefixes[0].Prefix.Mask.Size()
	assert.Equal(t, 64, length)

	pool := netip.MustParsePrefix("2001:db8:2::/48")
	addr, ok := netip.AddrFromSlice(prefixes[0].Prefix.IP)
	require.True(t, ok)
	assert.True(t, pool.Contains(addr.Unmap()), "delegated prefix %s is not inside %s", &prefixes[0].Prefix, pool)

	assert.NotNil(t, msg.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
}
