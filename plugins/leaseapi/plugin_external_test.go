// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leaseapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/plugins/leaseapi"
)

type source struct {
	name   string
	held   []leases.Lease
	pools  []leases.Pool
	family uint8
}

func (s *source) Name() string           { return s.name }
func (s *source) Leases() []leases.Lease { return s.held }
func (s *source) Pools() []leases.Pool   { return s.pools }

// v4Source is a stand-in for a range plugin: two IPv4 leases and a pool.
func v4Source() *source {
	return &source{
		name:   "range leases.sqlite3",
		family: 4,
		held: []leases.Lease{
			{
				Family:   4,
				Client:   "00:11:22:33:44:56",
				Address:  netip.MustParsePrefix("10.0.0.2/32"),
				Hostname: "desktop",
				Expires:  time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
				Source:   "range leases.sqlite3",
			},
			{
				Family:  4,
				Client:  "00:11:22:33:44:55",
				Address: netip.MustParsePrefix("10.0.0.1/32"),
				Expires: time.Date(2026, 9, 5, 11, 0, 0, 0, time.UTC),
				Source:  "range leases.sqlite3",
			},
		},
		pools: []leases.Pool{{
			Source:      "range leases.sqlite3",
			Family:      4,
			Range:       "10.0.0.1-10.0.0.100",
			Size:        100,
			Used:        2,
			Quarantined: 1,
		}},
	}
}

// v6Source is a stand-in for a prefix plugin: one delegation and a pool.
func v6Source() *source {
	return &source{
		name:   "prefix 2001:db8::/48",
		family: 6,
		held: []leases.Lease{{
			Family:  6,
			Client:  "00030001aabbccddeeff",
			Address: netip.MustParsePrefix("2001:db8:0:1::/64"),
			Expires: time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC),
			Source:  "prefix 2001:db8::/48",
		}},
		pools: []leases.Pool{{
			Source: "prefix 2001:db8::/48",
			Family: 6,
			Range:  "2001:db8::/48",
			Size:   65536,
			Used:   1,
		}},
	}
}

func register(t *testing.T, s leases.Source) {
	t.Helper()
	leases.Register(s)
	t.Cleanup(func() { leases.Unregister(s) })
}

// A socket path is capped at 104 bytes on darwin, hence the short temp dir.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cdhcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

// The window between closing this listener and the plugin rebinding the
// same address is negligible on loopback inside a test process.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// Ignores the URL's host entirely; every request dials path.
func unixClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

func get(t *testing.T, client *http.Client, method, url string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func serveOnSocket(t *testing.T) (*http.Client, string) {
	t.Helper()
	leaseapi.ResetRegistry(t)
	path := socketPath(t)
	h, err := leaseapi.Plugin.Setup4("unix:" + path)
	require.NoError(t, err)
	require.NotNil(t, h)
	return unixClient(path), "http://leaseapi"
}

func TestLeasesEndpoint(t *testing.T) {
	client, base := serveOnSocket(t)
	register(t, v4Source())
	register(t, v6Source())

	resp, body := get(t, client, http.MethodGet, base+"/v1/leases")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	// Sorted by source then address: prefix before range, .1 before .2.
	assert.JSONEq(t, `{"leases":[
		{"family":6,"client":"00030001aabbccddeeff","address":"2001:db8:0:1::/64",
		 "expires":"2026-09-05T13:00:00Z","static":false,"source":"prefix 2001:db8::/48"},
		{"family":4,"client":"00:11:22:33:44:55","address":"10.0.0.1/32",
		 "expires":"2026-09-05T11:00:00Z","static":false,"source":"range leases.sqlite3"},
		{"family":4,"client":"00:11:22:33:44:56","address":"10.0.0.2/32","hostname":"desktop",
		 "expires":"2026-09-05T12:00:00Z","static":false,"source":"range leases.sqlite3"}
	]}`, body)
}

func TestLeasesEndpointIsOrderedTheSameEveryTime(t *testing.T) {
	client, base := serveOnSocket(t)
	register(t, v4Source())
	register(t, v6Source())

	_, first := get(t, client, http.MethodGet, base+"/v1/leases")
	for range 5 {
		_, again := get(t, client, http.MethodGet, base+"/v1/leases")
		// Byte-identical, not merely equivalent, despite the sources iterating maps.
		assert.Equal(t, first, again)
	}
}

func TestLeasesEndpointWithNoSources(t *testing.T) {
	client, base := serveOnSocket(t)

	resp, body := get(t, client, http.MethodGet, base+"/v1/leases")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"leases":[]}`, body)
}

func TestPoolsEndpoint(t *testing.T) {
	client, base := serveOnSocket(t)
	register(t, v4Source())
	register(t, v6Source())
	// No pool of its own, the way the file plugin reports static reservations.
	register(t, &source{name: "file leases.txt", held: []leases.Lease{{
		Family: 4, Client: "00:11:22:33:44:57", Address: netip.MustParsePrefix("10.0.0.9/32"),
		Static: true, Source: "file leases.txt",
	}}})

	resp, body := get(t, client, http.MethodGet, base+"/v1/pools")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"pools":[
		{"source":"prefix 2001:db8::/48","family":6,"range":"2001:db8::/48",
		 "size":65536,"used":1,"quarantined":0},
		{"source":"range leases.sqlite3","family":4,"range":"10.0.0.1-10.0.0.100",
		 "size":100,"used":2,"quarantined":1}
	]}`, body)
}

func TestHealthEndpoint(t *testing.T) {
	client, base := serveOnSocket(t)

	resp, body := get(t, client, http.MethodGet, base+"/v1/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"ok":true,"sources":0}`, body)

	register(t, v4Source())
	register(t, v6Source())
	_, body = get(t, client, http.MethodGet, base+"/v1/health")
	assert.JSONEq(t, `{"ok":true,"sources":2}`, body)
}

func TestFilters(t *testing.T) {
	client, base := serveOnSocket(t)
	register(t, v4Source())
	register(t, v6Source())

	for _, tc := range []struct {
		name       string
		path       string
		wantLeases int
		wantPools  int
	}{
		{name: "family 4", path: "family=4", wantLeases: 2, wantPools: 1},
		{name: "family 6", path: "family=6", wantLeases: 1, wantPools: 1},
		{name: "one source", path: "source=range+leases.sqlite3", wantLeases: 2, wantPools: 1},
		{name: "both together", path: "family=6&source=prefix+2001%3Adb8%3A%3A%2F48", wantLeases: 1, wantPools: 1},
		{name: "a combination that matches nothing", path: "family=6&source=range+leases.sqlite3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := get(t, client, http.MethodGet, base+"/v1/leases?"+tc.path)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var got struct {
				Leases []leases.Lease `json:"leases"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &got))
			assert.Len(t, got.Leases, tc.wantLeases)

			resp, body = get(t, client, http.MethodGet, base+"/v1/pools?"+tc.path)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var pools struct {
				Pools []leases.Pool `json:"pools"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &pools))
			assert.Len(t, pools.Pools, tc.wantPools)
		})
	}
}

func TestRejectedRequests(t *testing.T) {
	client, base := serveOnSocket(t)
	register(t, v4Source())

	for _, tc := range []struct {
		name  string
		query string
		want  string
	}{
		{name: "a family that is not a family", query: "family=5", want: "family must be 4 or 6"},
		{name: "a family in another notation", query: "family=ipv4", want: "family must be 4 or 6"},
		{name: "an empty family", query: "family=", want: "family must be 4 or 6"},
		{name: "a source that is not registered", query: "source=range+other.sqlite3", want: "no such source"},
		{name: "an unknown parameter", query: "limit=10", want: "unknown query parameter, want family or source"},
		{name: "a misspelt parameter", query: "familly=4", want: "unknown query parameter, want family or source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{"/v1/leases", "/v1/pools"} {
				resp, body := get(t, client, http.MethodGet, base+path+"?"+tc.query)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
				assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
				assert.JSONEq(t, fmt.Sprintf(`{"error":%q}`, tc.want), body)
			}
		})
	}
}

func TestOnlyGETIsServed(t *testing.T) {
	client, base := serveOnSocket(t)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			resp, _ := get(t, client, method, base+"/v1/leases")
			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			// A GET pattern answers HEAD too; that's the mux's doing.
			assert.Equal(t, "GET, HEAD", resp.Header.Get("Allow"))
			// noStore wraps the whole mux, so even its own 405 carries it.
			assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		})
	}
}

func TestUnknownPath(t *testing.T) {
	client, base := serveOnSocket(t)

	for _, path := range []string{"/", "/v1", "/v1/leases/1", "/v2/leases", "/debug/pprof/"} {
		t.Run(path, func(t *testing.T) {
			resp, _ := get(t, client, http.MethodGet, base+path)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

func TestStreamsALargeAnswer(t *testing.T) {
	client, base := serveOnSocket(t)
	// Lowered from the shipped 100,000 so the streaming path runs without a
	// body of tens of megabytes for every test run.
	leaseapi.SetStreamThreshold(t, 100)

	const count = 5000
	held := make([]leases.Lease, 0, count)
	for i := range count {
		held = append(held, leases.Lease{
			Family:  4,
			Client:  fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256),
			Address: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}), 32),
			Source:  "range big.sqlite3",
		})
	}
	register(t, &source{name: "range big.sqlite3", held: held})

	resp, body := get(t, client, http.MethodGet, base+"/v1/leases")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got struct {
		Leases []leases.Lease `json:"leases"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	require.Len(t, got.Leases, count)
	assert.Equal(t, "10.0.0.0/32", got.Leases[0].Address.String())
}

func TestServesOnLoopbackTCP(t *testing.T) {
	leaseapi.ResetRegistry(t)
	addr := freeAddr(t)
	h, err := leaseapi.Plugin.Setup4("tcp:" + addr)
	require.NoError(t, err)
	require.NotNil(t, h)
	register(t, v4Source())

	resp, body := get(t, http.DefaultClient, http.MethodGet, "http://"+addr+"/v1/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"ok":true,"sources":1}`, body)
}

func TestRefusesANonLoopbackAddress(t *testing.T) {
	leaseapi.ResetRegistry(t)

	for _, addr := range []string{"tcp:0.0.0.0:9755", "tcp:192.0.2.1:9755", "tcp:[2001:db8::1]:9755", "tcp::9755"} {
		t.Run(addr, func(t *testing.T) {
			h, err := leaseapi.Plugin.Setup4(addr)
			require.Error(t, err)
			assert.Nil(t, h)
			assert.Contains(t, err.Error(), "unauthenticated")
			assert.Contains(t, err.Error(), "not a loopback address")
		})
	}
}

func TestSocketModeIsApplied(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want os.FileMode
	}{
		{name: "the default is owner only", want: 0o600},
		{name: "a group-readable socket", args: []string{"mode:0660"}, want: 0o660},
		{name: "a world-readable socket", args: []string{"mode:0666"}, want: 0o666},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaseapi.ResetRegistry(t)
			path := socketPath(t)

			_, err := leaseapi.Plugin.Setup4(append([]string{"unix:" + path}, tc.args...)...)
			require.NoError(t, err)

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, info.Mode().Perm())
			assert.NotZero(t, info.Mode()&os.ModeSocket, "the path must be a socket")
		})
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	leaseapi.ResetRegistry(t)
	path := socketPath(t)

	// A killed process leaves its socket behind; starting again must not need an operator to remove it.
	stale, err := net.Listen("unix", path)
	require.NoError(t, err)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	require.FileExists(t, path)

	h, err := leaseapi.Plugin.Setup4("unix:" + path)
	require.NoError(t, err)
	require.NotNil(t, h)

	resp, _ := get(t, unixClient(path), http.MethodGet, "http://leaseapi/v1/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestASecondServerOnTheSamePathIsRefused(t *testing.T) {
	leaseapi.ResetRegistry(t)
	path := socketPath(t)

	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	// Something is already answering there; either way this one has no business unlinking it.
	_, err = leaseapi.Plugin.Setup4("unix:" + path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already listening")
}

func TestSetup4AndSetup6ShareOneListener(t *testing.T) {
	leaseapi.ResetRegistry(t)
	path := socketPath(t)
	register(t, v4Source())

	h4, err := leaseapi.Plugin.Setup4("unix:" + path)
	require.NoError(t, err)
	require.NotNil(t, h4)
	// A second bind on this path would fail, so succeeding is what sharing looks like from outside.
	h6, err := leaseapi.Plugin.Setup6("unix:" + path)
	require.NoError(t, err)
	require.NotNil(t, h6)

	resp, body := get(t, unixClient(path), http.MethodGet, "http://leaseapi/v1/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"ok":true,"sources":1}`, body)
}

func TestASecondAddressIsRefused(t *testing.T) {
	leaseapi.ResetRegistry(t)
	first := socketPath(t)
	second := socketPath(t)

	_, err := leaseapi.Plugin.Setup4("unix:" + first)
	require.NoError(t, err)

	// One process, one registry, one endpoint: a second address is refused.
	_, err = leaseapi.Plugin.Setup6("unix:" + second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to also listen on")
	assert.NoFileExists(t, second)
}

func TestHandlersDoNothing(t *testing.T) {
	leaseapi.ResetRegistry(t)
	path := socketPath(t)

	h4, err := leaseapi.Plugin.Setup4("unix:" + path)
	require.NoError(t, err)
	h6, err := leaseapi.Plugin.Setup6("unix:" + path)
	require.NoError(t, err)

	resp4, stop4 := h4(nil, nil)
	assert.Nil(t, resp4)
	assert.False(t, stop4, "the plugin must never end the chain")

	resp6, stop6 := h6(nil, nil)
	assert.Nil(t, resp6)
	assert.False(t, stop6, "the plugin must never end the chain")
}
