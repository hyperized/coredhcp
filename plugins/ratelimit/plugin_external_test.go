// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ratelimit_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpiana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/ratelimit"
)

// Most tests below configure a rate of one request per minute, so the only
// tokens in play are the ones burst: put there. No amount of wall clock a test
// run can consume adds another, which makes the pass and drop sequence exact
// without reaching into the plugin's clock.
const slow = "1/m"

var (
	macA = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	macB = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
)

// ctxFrom builds the context the server hands a handler for a request from
// peer.
func ctxFrom(peer string) context.Context {
	return handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Interface: "eth0",
		IfIndex:   2,
		Peer:      netip.MustParseAddrPort(peer),
	})
}

// limiter4 is a configured DHCPv4 instance of the plugin, with the packet
// building every test would otherwise repeat wrapped around it.
type limiter4 struct {
	t *testing.T
	h handler.Handler4Ctx
}

func newLimiter4(t *testing.T, args ...string) limiter4 {
	t.Helper()
	h, err := ratelimit.Plugin.Setup4Ctx(args...)
	require.NoError(t, err)
	return limiter4{t: t, h: h}
}

// pass runs one Discovery from mac through the handler and reports whether
// the chain continued.
func (l limiter4) pass(ctx context.Context, mac net.HardwareAddr) bool {
	l.t.Helper()
	req, err := dhcpv4.NewDiscovery(mac)
	require.NoError(l.t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(l.t, err)

	got, stop := l.h(ctx, req, resp)
	if stop {
		assert.Nil(l.t, got, "a dropped request must not carry a response")
		return false
	}
	assert.Same(l.t, resp, got, "a passed request hands the response on unchanged")
	return true
}

// limiter6 is limiter4 for DHCPv6.
type limiter6 struct {
	t *testing.T
	h handler.Handler6Ctx
}

func newLimiter6(t *testing.T, args ...string) limiter6 {
	t.Helper()
	h, err := ratelimit.Plugin.Setup6Ctx(args...)
	require.NoError(t, err)
	return limiter6{t: t, h: h}
}

// pass runs one Solicit built from opts through the handler and reports
// whether the chain continued.
func (l limiter6) pass(ctx context.Context, opts ...dhcpv6.Modifier) bool {
	l.t.Helper()
	req, err := dhcpv6.NewMessage(opts...)
	require.NoError(l.t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(l.t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	got, stop := l.h(ctx, req, resp)
	if stop {
		assert.Nil(l.t, got, "a dropped request must not carry a response")
		return false
	}
	assert.Same(l.t, resp, got, "a passed request hands the response on unchanged")
	return true
}

// withMAC gives a DHCPv6 message a DUID-LL, which is where dhcpv6.ExtractMAC
// finds a hardware address when there is no relay in front of the client.
func withMAC(mac net.HardwareAddr) dhcpv6.Modifier {
	return dhcpv6.WithClientID(&dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: mac})
}

func TestPluginDeclaresOnlyTheContextAwareSetups(t *testing.T) {
	assert.Equal(t, "ratelimit", ratelimit.Plugin.Name)
	assert.NotNil(t, ratelimit.Plugin.Setup4Ctx)
	assert.NotNil(t, ratelimit.Plugin.Setup6Ctx)
	assert.Nil(t, ratelimit.Plugin.Setup4)
	assert.Nil(t, ratelimit.Plugin.Setup6)
	require.NoError(t, plugins.RegisterPlugin(&ratelimit.Plugin))
}

func TestSetupRejectsBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no rate"},
		{name: "rate without a period", args: []string{"20"}},
		{name: "rate of zero", args: []string{"0/s"}},
		{name: "unknown option", args: []string{"20/s", "window:5"}},
		{name: "option twice", args: []string{"20/s", "max:5", "max:6"}},
		{name: "bad per", args: []string{"20/s", "per:port"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := ratelimit.Plugin.Setup4Ctx(tc.args...)
			require.Error(t, err)
			assert.Nil(t, h4)

			h6, err := ratelimit.Plugin.Setup6Ctx(tc.args...)
			require.Error(t, err)
			assert.Nil(t, h6)
		})
	}
}

func TestHandler4SpendsTheBurstThenDrops(t *testing.T) {
	l := newLimiter4(t, slow, "burst:3")
	ctx := ctxFrom("192.0.2.10:68")

	for i := range 3 {
		assert.True(t, l.pass(ctx, macA), "request %d is inside the burst", i+1)
	}
	assert.False(t, l.pass(ctx, macA))
	assert.False(t, l.pass(ctx, macA))

	// A different client has a bucket of its own.
	assert.True(t, l.pass(ctx, macB))
}

func TestHandler4PerSourceKeysOnThePeer(t *testing.T) {
	l := newLimiter4(t, slow, "burst:1", "per:source")
	first := ctxFrom("192.0.2.10:68")
	second := ctxFrom("192.0.2.11:68")

	assert.True(t, l.pass(first, macA))
	// Same peer, different MAC: still the same bucket, and it is empty.
	assert.False(t, l.pass(first, macB))
	assert.True(t, l.pass(second, macA))
}

func TestHandler4PerBothKeysOnThePair(t *testing.T) {
	l := newLimiter4(t, slow, "burst:1", "per:both")
	relay := ctxFrom("192.0.2.1:67")
	other := ctxFrom("192.0.2.2:67")

	assert.True(t, l.pass(relay, macA))
	assert.False(t, l.pass(relay, macA))
	// Either half of the pair changing makes it a different client.
	assert.True(t, l.pass(relay, macB))
	assert.True(t, l.pass(other, macA))
}

func TestHandler4WithoutRequestInfoFallsBackToTheMAC(t *testing.T) {
	// The server always attaches RequestInfo, but a handler reached through
	// the legacy LoadPlugins API or straight from a test sees none, and has
	// to keep limiting rather than pass everything or lump every client into
	// one bucket.
	l := newLimiter4(t, slow, "burst:1", "per:source")

	assert.True(t, l.pass(context.Background(), macA))
	assert.False(t, l.pass(context.Background(), macA))
	assert.True(t, l.pass(context.Background(), macB))
}

func TestHandler4GlobalLimitCutsInAcrossClients(t *testing.T) {
	// Room for 60 requests per client, and one in total.
	l := newLimiter4(t, "60/s", "burst:60", "global:"+slow, "max:8")
	ctx := ctxFrom("192.0.2.10:68")

	assert.True(t, l.pass(ctx, macA))
	assert.False(t, l.pass(ctx, macB), "the shared bucket held one token")
	assert.False(t, l.pass(ctx, macA))
}

func TestHandler6KeysOnTheClient(t *testing.T) {
	l := newLimiter6(t, slow, "burst:1")
	ctx := ctxFrom("[2001:db8::1]:546")

	assert.True(t, l.pass(ctx, withMAC(macA)))
	assert.False(t, l.pass(ctx, withMAC(macA)))
	assert.True(t, l.pass(ctx, withMAC(macB)))
}

func TestHandler6KeysOnTheDUIDWhenThereIsNoMAC(t *testing.T) {
	l := newLimiter6(t, slow, "burst:1")
	ctx := ctxFrom("[2001:db8::1]:546")
	one := dhcpv6.WithClientID(&dhcpv6.DUIDEN{EnterpriseNumber: 42, EnterpriseIdentifier: []byte("one")})
	two := dhcpv6.WithClientID(&dhcpv6.DUIDEN{EnterpriseNumber: 42, EnterpriseIdentifier: []byte("two")})

	assert.True(t, l.pass(ctx, one))
	assert.False(t, l.pass(ctx, one))
	assert.True(t, l.pass(ctx, two))
}

func TestHandler6WithNeitherMACNorDUIDKeysOnThePeer(t *testing.T) {
	l := newLimiter6(t, slow, "burst:1", "per:both")
	first := ctxFrom("[2001:db8::1]:546")
	second := ctxFrom("[2001:db8::2]:546")

	assert.True(t, l.pass(first))
	assert.False(t, l.pass(first))
	assert.True(t, l.pass(second))
}

func TestHandler4IsSafeUnderConcurrentUse(t *testing.T) {
	// One instance, one goroutine per packet, which is how the server calls
	// it. The race detector is the point; the counts have to add up exactly
	// because no token is refilled inside a run this short.
	const (
		goroutines = 16
		perRoutine = 200
		keys       = 4
		burst      = 100
	)
	h, err := ratelimit.Plugin.Setup4Ctx(slow, "burst:100", "per:both", "max:4")
	require.NoError(t, err)

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0, 0, 0, 0, byte(g % keys)})
			assert.NoError(t, err)
			ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{
				Peer: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(g % keys)}), 68),
			})
			for range perRoutine {
				if _, stop := h(ctx, req, req); !stop {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(keys*burst), allowed.Load())
	assert.Greater(t, int64(goroutines*perRoutine), allowed.Load())
}

// benchRequest builds the packet a benchmark reuses, so the numbers measure
// the plugin and not dhcpv4 packet construction.
func benchRequest(b *testing.B, mac net.HardwareAddr) *dhcpv4.DHCPv4 {
	b.Helper()
	req, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		b.Fatal(err)
	}
	return req
}

func BenchmarkHandler4(b *testing.B) {
	ctx := handler.WithRequestInfo(context.Background(), handler.RequestInfo{
		Interface: "eth0",
		IfIndex:   2,
		Peer:      netip.MustParseAddrPort("192.0.2.10:68"),
	})

	// One client hammering the server, which is the path a flood takes and
	// the one that has to be free: a table hit, a move to the head of the LRU
	// that finds the bucket already there, and the bucket arithmetic.
	//
	// The bucket runs dry partway through, since no rate the plugin accepts
	// keeps up with a benchmark loop, so most iterations time a drop rather
	// than a pass. The two differ by one subtraction and the counter behind
	// the summary, and the drop is what a flood actually costs.
	b.Run("hot key", func(b *testing.B) {
		h, err := ratelimit.Plugin.Setup4Ctx("1000000/s")
		if err != nil {
			b.Fatal(err)
		}
		req := benchRequest(b, macA)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			h(ctx, req, req)
		}
	})

	// A stream of distinct clients that fits inside max: every key is a hit
	// after the first pass, and every hit moves a bucket through the list.
	b.Run("cycled keys", func(b *testing.B) {
		const keys = 1024
		h, err := ratelimit.Plugin.Setup4Ctx("1000000/s", "max:1024")
		if err != nil {
			b.Fatal(err)
		}
		reqs := make([]*dhcpv4.DHCPv4, keys)
		for i := range reqs {
			reqs[i] = benchRequest(b, net.HardwareAddr{0xaa, 0, 0, 0, byte(i >> 8), byte(i)})
			h(ctx, reqs[i], reqs[i]) // warm the table up
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			req := reqs[i%keys]
			h(ctx, req, req)
		}
	})

	// A client varying its MAC per packet, which is what someone who has read
	// this plugin's documentation does. Every request evicts and refiles a
	// bucket, so the key string is allocated each time.
	b.Run("new keys", func(b *testing.B) {
		h, err := ratelimit.Plugin.Setup4Ctx("1000000/s", "max:1024")
		if err != nil {
			b.Fatal(err)
		}
		req := benchRequest(b, macA)
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			req.ClientHWAddr[3] = byte(i >> 16)
			req.ClientHWAddr[4] = byte(i >> 8)
			req.ClientHWAddr[5] = byte(i)
			h(ctx, req, req)
		}
	})
}
