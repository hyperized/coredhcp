// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
)

// pluginStubBackend is a lookuper the handler and lookup tests can drive
// directly, without going through an HTTP server.
type pluginStubBackend struct {
	calls  int
	gotMAC string
	gotCtx context.Context
	result lookupResult
	err    error
}

func (s *pluginStubBackend) lookup(ctx context.Context, mac string) (lookupResult, error) {
	s.calls++
	s.gotMAC = mac
	s.gotCtx = ctx
	return s.result, s.err
}

func TestDefaultOptions(t *testing.T) {
	assert.Equal(t, options{
		ttl:         defaultTTL,
		negativeTTL: defaultNegativeTTL,
		timeout:     defaultTimeout,
		lifetime:    defaultLifetime,
	}, defaultOptions())
}

func TestOptionsParse(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    options
		wantErr string
	}{
		{
			name: "ttl only",
			args: []string{"ttl:10m"},
			want: options{ttl: 10 * time.Minute, negativeTTL: defaultNegativeTTL, timeout: defaultTimeout, lifetime: defaultLifetime},
		},
		{
			name: "negative-ttl only",
			args: []string{"negative-ttl:1m"},
			want: options{ttl: defaultTTL, negativeTTL: time.Minute, timeout: defaultTimeout, lifetime: defaultLifetime},
		},
		{
			name: "timeout only",
			args: []string{"timeout:2s"},
			want: options{ttl: defaultTTL, negativeTTL: defaultNegativeTTL, timeout: 2 * time.Second, lifetime: defaultLifetime},
		},
		{
			name: "lifetime only",
			args: []string{"lifetime:2h"},
			want: options{ttl: defaultTTL, negativeTTL: defaultNegativeTTL, timeout: defaultTimeout, lifetime: 2 * time.Hour},
		},
		{
			name: "several in one call",
			args: []string{"ttl:1m", "negative-ttl:2m", "timeout:3s", "lifetime:4h"},
			want: options{ttl: time.Minute, negativeTTL: 2 * time.Minute, timeout: 3 * time.Second, lifetime: 4 * time.Hour},
		},
		{
			name:    "bad duration",
			args:    []string{"ttl:nope"},
			wantErr: `the duration in "ttl:nope" does not parse`,
		},
		{
			name:    "zero duration",
			args:    []string{"ttl:0s"},
			wantErr: `the duration in "ttl:0s" is not positive`,
		},
		{
			name:    "negative duration",
			args:    []string{"ttl:-1s"},
			wantErr: `the duration in "ttl:-1s" is not positive`,
		},
		{
			name:    "unknown argument",
			args:    []string{"bogus"},
			wantErr: `unexpected argument "bogus"`,
		},
		{
			name:    "unknown argument that looks like one of ours",
			args:    []string{"ttl=5m"},
			wantErr: `unexpected argument "ttl=5m"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := defaultOptions()
			err := o.parse(tc.args)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				// An argument that isn't one of the known prefixes should
				// name what is accepted, not just what was rejected.
				if tc.name == "unknown argument" || tc.name == "unknown argument that looks like one of ours" {
					assert.Contains(t, err.Error(), knownOptions())
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, o)
		})
	}
}

func TestKnownOptions(t *testing.T) {
	// The documented order in the package comment: ttl, negative-ttl,
	// timeout, lifetime.
	assert.Equal(t, "ttl:, negative-ttl:, timeout:, lifetime:", knownOptions())
}

func TestSetupStateErrors(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		setup   func(t *testing.T)
		wantErr string
	}{
		{
			name:    "no arguments",
			args:    nil,
			wantErr: "give the NetBox URL and the API token first",
		},
		{
			name:    "one argument",
			args:    []string{"https://netbox.example.com"},
			wantErr: "give the NetBox URL and the API token first",
		},
		{
			name:    "bad URL",
			args:    []string{"ftp://netbox.example.com", "sometoken"},
			wantErr: "has no http or https scheme",
		},
		{
			name: "bad token, missing environment variable",
			args: []string{"https://netbox.example.com", "env:NETBOX_TEST_SETUP_STATE_MISSING"},
			setup: func(t *testing.T) {
				t.Helper()
				// Set-but-empty behaves the same as unset for resolveToken,
				// and is deterministic, unlike hoping a name is unset.
				t.Setenv("NETBOX_TEST_SETUP_STATE_MISSING", "")
			},
			wantErr: "unset or empty",
		},
		{
			name:    "bad trailing argument",
			args:    []string{"https://netbox.example.com", "sometoken", "bogus"},
			wantErr: `"bogus"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			p, err := setupState(tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Nil(t, p)
		})
	}
}

func TestSetupStateSuccess(t *testing.T) {
	p, err := setupState("https://netbox.example.com", "sometoken", "ttl:1m")
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.Equal(t, time.Minute, p.opts.ttl)
	assert.Equal(t, defaultNegativeTTL, p.opts.negativeTTL)
	assert.Equal(t, defaultTimeout, p.opts.timeout)
	assert.Equal(t, defaultLifetime, p.opts.lifetime)
	assert.NotNil(t, p.cache)
	assert.NotNil(t, p.backend)
	assert.NotNil(t, p.now)
}

func TestPluginStateLookup(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	v4 := netip.MustParsePrefix("10.0.0.5/24")

	t.Run("a second call before the TTL is served from the cache", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		_, err = p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, 1, stub.calls)
	})

	t.Run("a positive result expires after the TTL", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		opts := defaultOptions()
		p := &pluginState{backend: stub, cache: newCache(16), opts: opts, now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		now = now.Add(opts.ttl)
		_, err = p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, 2, stub.calls)
	})

	t.Run("a not-found result is cached under the negative TTL, not the TTL", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: false}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		opts := defaultOptions()
		p := &pluginState{backend: stub, cache: newCache(16), opts: opts, now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		// Past the negative TTL but nowhere near the (much longer) positive
		// one, so this only proves anything if the miss used negativeTTL.
		now = now.Add(opts.negativeTTL)
		_, err = p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, 2, stub.calls)
	})

	t.Run("a backend error is returned and never cached", func(t *testing.T) {
		stub := &pluginStubBackend{err: errors.New("netbox is down")}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.Error(t, err)
		_, err = p.lookup(context.Background(), mac)
		require.Error(t, err)
		assert.Equal(t, 2, stub.calls)
	})

	t.Run("the backend sees the canonical lowercase MAC string", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, mac.String(), stub.gotMAC)
	})

	t.Run("ErrNoInterface is an answer, not a failure, and is cached under the negative TTL", func(t *testing.T) {
		stub := &pluginStubBackend{err: fmt.Errorf("MAC address %s: %w", mac, ErrNoInterface)}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		opts := defaultOptions()
		p := &pluginState{backend: stub, cache: newCache(16), opts: opts, now: func() time.Time { return now }}

		result, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, lookupResult{}, result)
		assert.Equal(t, 1, stub.calls)

		_, err = p.lookup(context.Background(), mac)
		require.NoError(t, err)
		assert.Equal(t, 1, stub.calls, "the cached negative result must keep the second call off the backend")

		cached, ok := p.cache.get(mac.String(), now)
		require.True(t, ok)
		assert.Equal(t, lookupResult{}, cached)
	})

	t.Run("the timeout becomes a deadline the backend sees", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		opts := defaultOptions()
		opts.timeout = 5 * time.Second
		p := &pluginState{backend: stub, cache: newCache(16), opts: opts, now: func() time.Time { return now }}

		_, err := p.lookup(context.Background(), mac)
		require.NoError(t, err)
		require.NotNil(t, stub.gotCtx)
		deadline, ok := stub.gotCtx.Deadline()
		require.True(t, ok, "the backend must see a deadline derived from the configured timeout")
		assert.WithinDuration(t, time.Now().Add(opts.timeout), deadline, time.Second)
	})

	t.Run("a cancelled context reaches the backend", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: func() time.Time { return now }}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := p.lookup(ctx, mac)
		require.NoError(t, err) // the stub itself does not look at ctx.Err
		require.NotNil(t, stub.gotCtx)
		assert.ErrorIs(t, stub.gotCtx.Err(), context.Canceled)
	})
}

// pluginV4Exchange builds a DHCPDISCOVER and the reply frame for it, both
// with a real (non-nil) Options map, the way a server would hand them to a
// handler.
func pluginV4Exchange(t *testing.T, mac net.HardwareAddr) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.NewDiscovery(mac)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

func TestHandler4(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	t.Run("DHCPINFORM passes through untouched", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("DHCPRELEASE passes through untouched without a lookup", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("DHCPDECLINE passes through untouched without a lookup", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("backend error drops the request", func(t *testing.T) {
		stub := &pluginStubBackend{err: errors.New("netbox is down")}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Nil(t, gotResp)
		assert.True(t, stop)
	})

	t.Run("MAC not found in NetBox passes through", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: false}}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)
		wantYourIP := resp.YourIPAddr // must stay whatever NewReplyFromRequest set it to

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, wantYourIP, gotResp.YourIPAddr)
	})

	t.Run("found but the interface has no IPv4 address", func(t *testing.T) {
		v6 := netip.MustParsePrefix("2001:db8::10:5/64")
		stub := &pluginStubBackend{result: lookupResult{found: true, v6: v6}}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)
		wantYourIP := resp.YourIPAddr

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, wantYourIP, gotResp.YourIPAddr)
	})

	t.Run("found with an IPv4 address", func(t *testing.T) {
		v4 := netip.MustParsePrefix("10.0.0.5/24")
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, resp := pluginV4Exchange(t, mac)

		gotResp, stop := p.Handler4(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.True(t, stop)
		assert.Equal(t, net.IP(v4.Addr().AsSlice()), gotResp.YourIPAddr)

		mask := gotResp.SubnetMask()
		require.NotNil(t, mask)
		assert.Equal(t, net.CIDRMask(v4.Bits(), 32), mask)
		// IPMask.String() is hex ("ffffff00"); reading it back as an IP
		// gives the dotted-decimal form an operator would recognise.
		assert.Equal(t, "255.255.255.0", net.IP(mask).String())
	})
}

func TestHandler6(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	t.Run("cannot decapsulate", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		// A RelayMessage with no embedded relay-message option fails to
		// decapsulate.
		req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Nil(t, gotResp)
		assert.True(t, stop)
	})

	t.Run("no address requested", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("IA_NA present but no MAC can be extracted", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		// An IA_NA is present (so the OneIANA check passes) but there is no
		// client ID option to derive a MAC from.
		req, err := dhcpv6.NewMessage(dhcpv6.WithIANA())
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("Release passes through untouched without a lookup", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		// Built from NewSolicit so an IA_NA and an extractable MAC are both
		// present; the type check must still short-circuit before either is
		// consulted.
		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRelease
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("Decline passes through untouched without a lookup", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeDecline
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("a relayed Decline is skipped by the inner message type, not the outer one", func(t *testing.T) {
		stub := &pluginStubBackend{}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		inner, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		inner.MessageType = dhcpv6.MessageTypeDecline

		// The relay wrapper's own type is RELAY-FORW, never Decline; only the
		// encapsulated message carries the client's real type.
		relay, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward,
			net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
		require.NoError(t, err)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), relay, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Equal(t, 0, stub.calls)
	})

	t.Run("backend error drops the request", func(t *testing.T) {
		stub := &pluginStubBackend{err: errors.New("netbox is down")}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Nil(t, gotResp)
		assert.True(t, stop)
	})

	t.Run("MAC not found in NetBox passes through", func(t *testing.T) {
		stub := &pluginStubBackend{result: lookupResult{found: false}}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Empty(t, gotResp.GetOption(dhcpv6.OptionIANA))
	})

	t.Run("found but the interface has no IPv6 address", func(t *testing.T) {
		v4 := netip.MustParsePrefix("10.0.0.5/24")
		stub := &pluginStubBackend{result: lookupResult{found: true, v4: v4}}
		p := &pluginState{backend: stub, cache: newCache(16), opts: defaultOptions(), now: clock}

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.Same(t, resp, gotResp)
		assert.False(t, stop)
		assert.Empty(t, gotResp.GetOption(dhcpv6.OptionIANA))
	})

	t.Run("found with an IPv6 address", func(t *testing.T) {
		v6 := netip.MustParsePrefix("2001:db8::10:5/64")
		stub := &pluginStubBackend{result: lookupResult{found: true, v6: v6}}
		opts := defaultOptions()
		// A non-default lifetime proves the option carries the configured
		// value rather than some other hardcoded default.
		opts.lifetime = 90 * time.Minute
		p := &pluginState{backend: stub, cache: newCache(16), opts: opts, now: clock}

		req, err := dhcpv6.NewSolicit(mac)
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		gotResp, stop := p.Handler6(context.Background(), req, resp)
		assert.False(t, stop)

		reqIANA := req.Options.OneIANA()
		require.NotNil(t, reqIANA)

		iaOpts := gotResp.GetOption(dhcpv6.OptionIANA)
		require.Len(t, iaOpts, 1)
		gotIANA, ok := iaOpts[0].(*dhcpv6.OptIANA)
		require.True(t, ok)
		assert.Equal(t, reqIANA.IaId, gotIANA.IaId)

		addrs := gotIANA.Options.Addresses()
		require.Len(t, addrs, 1)
		assert.Equal(t, net.IP(v6.Addr().AsSlice()), addrs[0].IPv6Addr)
		assert.Equal(t, opts.lifetime, addrs[0].PreferredLifetime)
		assert.Equal(t, opts.lifetime, addrs[0].ValidLifetime)
	})
}

// captureLog redirects the shared logger to a buffer for the duration of the
// test. The logger's console writer is process-wide, so a test using this
// must not run in parallel with another one that logs.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logger.WithConsole(&buf)
	t.Cleanup(func() { logger.WithConsole(os.Stderr) })
	return &buf
}

func TestLogLookupFailureLevel(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	cases := []struct {
		name      string
		err       error
		wantLevel string
	}{
		{
			name:      "an unauthorized response is a configuration fault",
			err:       fmt.Errorf("wrap: %w", ErrUnauthorized),
			wantLevel: "ERROR",
		},
		{
			name:      "a not-found response is a configuration fault",
			err:       fmt.Errorf("wrap: %w", ErrNotFound),
			wantLevel: "ERROR",
		},
		{
			name:      "netbox unavailable is treated as transient",
			err:       fmt.Errorf("wrap: %w", ErrUnavailable),
			wantLevel: "WARN",
		},
		{
			name:      "a plain transport error is treated as transient",
			err:       errors.New("dial tcp: connection refused"),
			wantLevel: "WARN",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			logLookupFailure(mac, tc.err)
			assert.Contains(t, buf.String(), "level="+tc.wantLevel)
		})
	}
}
