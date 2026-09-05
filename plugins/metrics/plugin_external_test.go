// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package metrics_test

import (
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/metrics"
)

// freeAddr grabs a free loopback port by binding to :0 and closing immediately; the reuse race is negligible on loopback in one test process.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestSetup4ArgumentValidation(t *testing.T) {
	metrics.ResetRegistry(t)

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "zero args", args: nil, wantErr: "expected exactly one argument"},
		{name: "two args", args: []string{"127.0.0.1:9754", "extra"}, wantErr: "expected exactly one argument"},
		{name: "address with no port", args: []string{"127.0.0.1"}, wantErr: "invalid listen address"},
		{name: "garbage address", args: []string{"nonsense"}, wantErr: "invalid listen address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := metrics.Plugin.Setup4(tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Nil(t, h)
		})
	}
}

func TestSetup6ArgumentValidation(t *testing.T) {
	metrics.ResetRegistry(t)

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "zero args", args: nil, wantErr: "expected exactly one argument"},
		{name: "two args", args: []string{"127.0.0.1:9754", "extra"}, wantErr: "expected exactly one argument"},
		{name: "address with no port", args: []string{"127.0.0.1"}, wantErr: "invalid listen address"},
		{name: "garbage address", args: []string{"nonsense"}, wantErr: "invalid listen address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := metrics.Plugin.Setup6(tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Nil(t, h)
		})
	}
}

func TestSharedListener(t *testing.T) {
	metrics.ResetRegistry(t)

	addr := freeAddr(t)

	h4, err := metrics.Plugin.Setup4(addr)
	require.NoError(t, err)
	assert.NotNil(t, h4)

	h6, err := metrics.Plugin.Setup6(addr)
	require.NoError(t, err)
	assert.NotNil(t, h6)
}

func TestConflictingAddress(t *testing.T) {
	t.Run("v4 first, v6 conflicts", func(t *testing.T) {
		metrics.ResetRegistry(t)
		addrA := freeAddr(t)
		addrB := freeAddr(t)

		_, err := metrics.Plugin.Setup4(addrA)
		require.NoError(t, err)

		_, err = metrics.Plugin.Setup6(addrB)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already listening on")
		assert.Contains(t, err.Error(), addrA)
		assert.Contains(t, err.Error(), addrB)
	})

	t.Run("v6 first, v4 conflicts", func(t *testing.T) {
		metrics.ResetRegistry(t)
		addrA := freeAddr(t)
		addrB := freeAddr(t)

		_, err := metrics.Plugin.Setup6(addrA)
		require.NoError(t, err)

		_, err = metrics.Plugin.Setup4(addrB)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already listening on")
		assert.Contains(t, err.Error(), addrA)
		assert.Contains(t, err.Error(), addrB)
	})
}

func TestBindFailure(t *testing.T) {
	metrics.ResetRegistry(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	_, err = metrics.Plugin.Setup4(ln.Addr().String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot listen on")
}

func TestEndToEnd(t *testing.T) {
	metrics.ResetRegistry(t)

	addr := freeAddr(t)

	handle4, err := metrics.Plugin.Setup4(addr)
	require.NoError(t, err)
	handle6, err := metrics.Plugin.Setup6(addr)
	require.NoError(t, err)

	v4req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	require.NoError(t, err)
	v4resp, err := dhcpv4.NewReplyFromRequest(v4req)
	require.NoError(t, err)

	gotResp4, stop4 := handle4(v4req, v4resp)
	assert.False(t, stop4)
	assert.Same(t, v4resp, gotResp4)

	v6req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	v6req.MessageType = dhcpv6.MessageTypeSolicit
	v6resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	v6resp.MessageType = dhcpv6.MessageTypeReply

	gotResp6, stop6 := handle6(v6req, v6resp)
	assert.False(t, stop6)
	assert.Same(t, v6resp, gotResp6)

	// Setup binds synchronously, so the listener is already accepting by now.
	resp, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	goVersion := strings.ReplaceAll(strings.ToLower(runtime.Version()), " ", "_")
	want := strings.Join([]string{
		"# HELP coredhcp_build_info Version information about the running coredhcp binary.",
		"# TYPE coredhcp_build_info gauge",
		`coredhcp_build_info{goversion="` + goVersion + `"} 1`,
		"# HELP coredhcp_requests_total Number of DHCP requests received, by IP family and message type.",
		"# TYPE coredhcp_requests_total counter",
		`coredhcp_requests_total{family="4",type="discover"} 1`,
		`coredhcp_requests_total{family="6",type="solicit"} 1`,
		"",
	}, "\n")
	assert.Equal(t, want, string(body))
}

func TestMethodAndPathRejection(t *testing.T) {
	metrics.ResetRegistry(t)

	addr := freeAddr(t)
	_, err := metrics.Plugin.Setup4(addr)
	require.NoError(t, err)

	base := "http://" + addr

	t.Run("POST to /metrics is not allowed", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, base+"/metrics", nil)
		require.NoError(t, err)

		client := http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("GET on another path is not found", func(t *testing.T) {
		resp, err := http.Get(base + "/nope")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
