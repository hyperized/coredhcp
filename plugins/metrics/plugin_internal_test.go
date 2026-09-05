// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package metrics

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ResetRegistry stops every listener and clears the registry; it lives here because shipped code can't do this.
func ResetRegistry(t *testing.T) {
	t.Helper()
	resetRegistry()
	t.Cleanup(resetRegistry)
}

func resetRegistry() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for addr, c := range registry.listeners {
		_ = c.srv.Close()
		// Waiting for Serve to return frees the port before the next test starts.
		<-c.done
		delete(registry.listeners, addr)
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "dhcpv4 message type", in: "DISCOVER", want: "discover"},
		{name: "dhcpv6 hyphenated type", in: "INFORMATION-REQUEST", want: "information-request"},
		{name: "unknown type has a space", in: "unknown (42)", want: "unknown_(42)"},
		{name: "empty", in: "", want: ""},
		{name: "quote is escaped", in: `a"b`, want: `a\"b`},
		{name: "backslash is escaped", in: `a\b`, want: `a\\b`},
		{name: "newline is escaped", in: "a\nb", want: `a\nb`},
		{name: "backslash is not double escaped", in: `\"`, want: `\\\"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeLabelValue(tc.in))
		})
	}
}

func TestListenAddr(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{name: "no args", args: nil, wantErr: "expected exactly one argument"},
		{name: "two args", args: []string{"127.0.0.1:9754", "extra"}, wantErr: "expected exactly one argument"},
		{name: "missing port", args: []string{"127.0.0.1"}, wantErr: "invalid listen address"},
		{name: "not an address", args: []string{"nonsense"}, wantErr: "invalid listen address"},
		{name: "host and port", args: []string{"127.0.0.1:9754"}, want: "127.0.0.1:9754"},
		{name: "port only", args: []string{":9754"}, want: ":9754"},
		{name: "surrounding whitespace is trimmed", args: []string{"  127.0.0.1:9754\t"}, want: "127.0.0.1:9754"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listenAddr(tc.args)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestObtain(t *testing.T) {
	t.Run("same address returns the same collector", func(t *testing.T) {
		ResetRegistry(t)

		first, err := obtain("127.0.0.1:0")
		require.NoError(t, err)
		second, err := obtain("127.0.0.1:0")
		require.NoError(t, err)
		assert.Same(t, first, second)
		assert.Len(t, registry.listeners, 1)
	})

	t.Run("a second address is a setup error naming both", func(t *testing.T) {
		ResetRegistry(t)

		c, err := obtain("127.0.0.1:0")
		require.NoError(t, err)
		running := c.ln.Addr().String()

		_, err = obtain("127.0.0.2:9754")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "127.0.0.1:0")
		assert.Contains(t, err.Error(), "127.0.0.2:9754")
		assert.Len(t, registry.listeners, 1)
		assert.NotEqual(t, running, "127.0.0.2:9754")
	})

	t.Run("bind failure is a setup error", func(t *testing.T) {
		ResetRegistry(t)

		_, err := obtain("127.0.0.1:not-a-port")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot listen on")
		assert.Empty(t, registry.listeners)
	})
}

func TestCollectorExpose(t *testing.T) {
	c := newTestCollector()

	c.count(family4, "discover")
	c.count(family4, "discover")
	c.count(family6, "solicit")
	c.count(family6, "information-request")

	assert.Equal(t, strings.Join([]string{
		"# HELP coredhcp_build_info Version information about the running coredhcp binary.",
		"# TYPE coredhcp_build_info gauge",
		`coredhcp_build_info{goversion="` + wantGoVersion() + `"} 1`,
		"# HELP coredhcp_requests_total Number of DHCP requests received, by IP family and message type.",
		"# TYPE coredhcp_requests_total counter",
		`coredhcp_requests_total{family="4",type="discover"} 2`,
		`coredhcp_requests_total{family="6",type="information-request"} 1`,
		`coredhcp_requests_total{family="6",type="solicit"} 1`,
		"",
	}, "\n"), string(c.expose()))
}

func TestCollectorExposeWithoutSamples(t *testing.T) {
	assert.Equal(t, strings.Join([]string{
		"# HELP coredhcp_build_info Version information about the running coredhcp binary.",
		"# TYPE coredhcp_build_info gauge",
		`coredhcp_build_info{goversion="` + wantGoVersion() + `"} 1`,
		"# HELP coredhcp_requests_total Number of DHCP requests received, by IP family and message type.",
		"# TYPE coredhcp_requests_total counter",
		"",
	}, "\n"), string(newTestCollector().expose()))
}

func TestCollectorCountIsRaceFree(t *testing.T) {
	const (
		goroutines = 8
		perRoutine = 250
	)
	c := newTestCollector()

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			for range perRoutine {
				// i%2 splits goroutines: half create a new series, half hammer an existing one.
				c.count(family4, fmt.Sprintf("type-%d", i%2))
			}
		}()
	}
	wg.Wait()

	var total uint64
	c.mu.RLock()
	for _, ctr := range c.requests {
		total += ctr.Load()
	}
	c.mu.RUnlock()
	assert.Equal(t, uint64(goroutines*perRoutine), total)
	assert.Len(t, c.requests, 2)
}

func TestMsgType6(t *testing.T) {
	solicit, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	solicit.MessageType = dhcpv6.MessageTypeSolicit

	relayed, err := dhcpv6.EncapsulateRelay(solicit, dhcpv6.MessageTypeRelayForward, net.IPv6loopback, net.IPv6loopback)
	require.NoError(t, err)

	unknown, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	unknown.MessageType = dhcpv6.MessageType(200)

	for _, tc := range []struct {
		name string
		req  dhcpv6.DHCPv6
		want string
	}{
		{name: "plain message", req: solicit, want: "solicit"},
		{name: "relayed message is decapsulated", req: relayed, want: "solicit"},
		{name: "unrecognised type keeps the number", req: unknown, want: "unknown_(200)"},
		{
			name: "undecapsulatable relay counts as unknown",
			req:  &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward},
			want: typeUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, msgType6(tc.req))
		})
	}
}

func TestHandlersDoNotTouchTheResponse(t *testing.T) {
	c := newTestCollector()

	t.Run("v4", func(t *testing.T) {
		req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		require.NoError(t, err)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		before := stub.Summary()

		resp, stop := c.Handler4(req, stub)
		assert.False(t, stop)
		assert.Same(t, stub, resp)
		assert.Equal(t, before, stub.Summary())
	})

	t.Run("v6", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeSolicit
		stub, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		stub.MessageType = dhcpv6.MessageTypeReply
		before := stub.Summary()

		resp, stop := c.Handler6(req, stub)
		assert.False(t, stop)
		assert.Same(t, stub, resp)
		assert.Equal(t, before, stub.Summary())
	})
}

// failingResponseWriter fails every write, simulating a scraper that disconnects mid-response.
type failingResponseWriter struct {
	header http.Header
}

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset")
}

func (*failingResponseWriter) WriteHeader(int) {}

func TestServeMetricsWriteFailure(t *testing.T) {
	c := newTestCollector()
	w := &failingResponseWriter{}

	// A write failure must not panic or touch counters; it's logged and dropped.
	c.serveMetrics(w, httpGet(t, "/metrics"))
	assert.Equal(t, contentType, w.Header().Get("Content-Type"))
}

func TestServeLoopLogsAListenerFailure(t *testing.T) {
	c, err := newCollector("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.srv.Close() })

	// Closing the listener under Serve triggers something other than ErrServerClosed, the branch that logs.
	require.NoError(t, c.ln.Close())
	<-c.done
}

func newTestCollector() *collector {
	return &collector{
		done:     make(chan struct{}),
		requests: make(map[requestKey]*atomic.Uint64),
	}
}

func httpGet(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	return req
}

// wantGoVersion reproduces expose's sanitising by hand so the assertion doesn't depend on sanitizeLabelValue.
func wantGoVersion() string {
	return strings.ReplaceAll(strings.ToLower(runtime.Version()), " ", "_")
}

func TestSeriesIsIdempotent(t *testing.T) {
	// The loser of the read-to-write lock race in series must get the winner's counter, not create one.
	c := newTestCollector()
	k := requestKey{family: family4, msgType: "discover"}

	first := c.series(k)
	assert.Same(t, first, c.series(k))
	assert.Len(t, c.requests, 1)
}
