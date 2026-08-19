// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build integration

// These tests drive the plugin's handlers against a real Redis server. Set
// REDIS_ADDR to a host:port or a redis:// URL, and REDIS_PASSWORD when the
// server wants one. `make test-redis` brings both up in compose and runs
// them; without REDIS_ADDR they skip.

package redis

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationPlugin builds an instance against REDIS_ADDR under a key prefix
// nothing else is using.
func integrationPlugin(t *testing.T) *pluginState {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR is not set, skipping: this test needs a real redis server")
	}
	// Keys are namespaced per run, so a shared server or a run that left
	// something behind cannot decide the outcome of this one.
	prefix := fmt.Sprintf("coredhcp-itest:%d:%d:", os.Getpid(), time.Now().UnixNano())
	args := []string{addr, "prefix:" + prefix, "timeout:5s"}
	if os.Getenv("REDIS_PASSWORD") != "" {
		args = append(args, "password:env:REDIS_PASSWORD")
	}

	p, err := setupState(args...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.client.Close() })

	// setupState only warns when the server stays quiet. Here the server is
	// the point of the test, so it has to answer.
	require.NoError(t, p.client.ping())
	return p
}

// writeFixture stores one client's hash through the plugin's own client and
// removes it again afterwards.
func writeFixture(t *testing.T, p *pluginState, fields map[string]string) {
	t.Helper()
	key := p.prefix + testMAC.String()
	require.NoError(t, p.client.hset(key, fields))
	t.Cleanup(func() { assert.NoError(t, p.client.del(key)) })
}

func TestIntegrationHandler4(t *testing.T) {
	p := integrationPlugin(t)
	writeFixture(t, p, map[string]string{
		fieldIPv4:      "10.0.0.5/24",
		fieldRouter:    "10.0.0.1",
		fieldDNS:       "10.0.0.2,2001:db8::2",
		fieldLeaseTime: "12h",
	})

	req, resp := v4Exchange(t, dhcpv4.MessageTypeDiscover,
		dhcpv4.WithRequestedOptions(dhcpv4.OptionDomainNameServer))
	got, stop := p.Handler4(req, resp)

	require.NotNil(t, got)
	assert.True(t, stop)
	assert.Equal(t, "10.0.0.5", got.YourIPAddr.String())
	assert.Equal(t, net.CIDRMask(24, 32), got.SubnetMask())
	assert.Equal(t, []net.IP{net.IP{10, 0, 0, 1}.To4()}, got.Router())
	assert.Equal(t, []net.IP{net.IP{10, 0, 0, 2}.To4()}, got.DNS())
	assert.Equal(t, 12*time.Hour, got.IPAddressLeaseTime(0))
}

func TestIntegrationHandler6(t *testing.T) {
	p := integrationPlugin(t)
	writeFixture(t, p, map[string]string{
		fieldIPv6:      "2001:db8::10:1",
		fieldDNS:       "10.0.0.2,2001:db8::2",
		fieldLeaseTime: "6h",
	})

	req, resp := v6Exchange(t, dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer))
	got, stop := p.Handler6(req, resp)

	require.NotNil(t, got)
	assert.False(t, stop)
	iana, ok := got.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
	require.True(t, ok, "want an IA_NA in the response")
	addr := iana.Options.OneAddress()
	require.NotNil(t, addr)
	assert.Equal(t, "2001:db8::10:1", addr.IPv6Addr.String())
	assert.Equal(t, 6*time.Hour, addr.PreferredLifetime)
	assert.Equal(t, 6*time.Hour, addr.ValidLifetime)

	dns := resp.Options.DNS()
	require.Len(t, dns, 1)
	assert.Equal(t, "2001:db8::2", dns[0].String())
}

// TestIntegrationUnknownMAC checks the pass-through against a real server:
// an empty hash has to look different from a failed lookup.
func TestIntegrationUnknownMAC(t *testing.T) {
	p := integrationPlugin(t)

	req, resp := v4Exchange(t, dhcpv4.MessageTypeDiscover)
	got, stop := p.Handler4(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
	assert.True(t, got.YourIPAddr.IsUnspecified())
}

// TestIntegrationPoolReuse runs enough lookups to be sure the pooled
// connection survives being handed back and picked up again, which the unit
// tests only prove against a server of our own making.
func TestIntegrationPoolReuse(t *testing.T) {
	p := integrationPlugin(t)
	writeFixture(t, p, map[string]string{fieldIPv4: "10.0.0.5"})

	for i := range 5 {
		req, resp := v4Exchange(t, dhcpv4.MessageTypeDiscover)
		got, stop := p.Handler4(req, resp)
		require.NotNil(t, got, "lookup %d", i)
		require.True(t, stop, "lookup %d", i)
		assert.Equal(t, "10.0.0.5", got.YourIPAddr.String())
	}
	assert.Equal(t, 1, p.client.idleCount(), "one connection should serve them all")
}
