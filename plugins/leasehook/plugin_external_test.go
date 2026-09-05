// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasehook_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/leasehook"
)

// A successful setup's worker has no public stop, same as in the server, so
// each test that sets the plugin up successfully leaves a goroutine parked
// on its queue until the binary exits — kept to two tests for that reason.

const testSecret = "s3cr3t"

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

type posted struct {
	body   []byte
	header http.Header
}

func newEndpoint(t *testing.T) (*httptest.Server, <-chan posted) {
	t.Helper()
	got := make(chan posted, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request body: %v", err)
			return
		}
		got <- posted{body: body, header: r.Header.Clone()}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func await(t *testing.T, got <-chan posted) posted {
	t.Helper()
	select {
	case p := <-got:
		return p
	case <-time.After(10 * time.Second):
		t.Fatal("the endpoint was never posted to")
		return posted{}
	}
}

func signatureOf(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestPluginIsRegisteredForBothFamilies(t *testing.T) {
	assert.Equal(t, "leasehook", leasehook.Plugin.Name)
	assert.NotNil(t, leasehook.Plugin.Setup4)
	assert.NotNil(t, leasehook.Plugin.Setup6)
	// Plain setup functions: the plugin reads nothing but the packets, so a
	// chain holding only plugins like this one needs no request context.
	assert.Nil(t, leasehook.Plugin.Setup4Ctx)
	assert.Nil(t, leasehook.Plugin.Setup6Ctx)
}

func TestSetupRejectsBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no target", args: nil},
		{name: "both targets", args: []string{"url:http://h/x", "exec:/bin/true"}},
		{name: "an unknown key", args: []string{"exec:/bin/true", "retry:3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := leasehook.Plugin.Setup4(tc.args...)
			require.Error(t, err)
			assert.Nil(t, h4)

			h6, err := leasehook.Plugin.Setup6(tc.args...)
			require.Error(t, err)
			assert.Nil(t, h6)
		})
	}
}

func TestSetup4ReportsAnAck(t *testing.T) {
	srv, got := newEndpoint(t)
	handle, err := leasehook.Plugin.Setup4("url:"+srv.URL, "secret:"+testSecret, "events:ack")
	require.NoError(t, err)
	require.NotNil(t, handle)

	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(testMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptHostName("laptop")),
	)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(net.IPv4(10, 0, 0, 5)),
		dhcpv4.WithLeaseTime(3600),
	)
	require.NoError(t, err)

	out, stop := handle(req, resp)
	assert.Same(t, resp, out, "the response is handed on untouched")
	assert.False(t, stop, "the chain is never ended here")

	p := await(t, got)
	assert.Equal(t, signatureOf(testSecret, p.body), p.header.Get("X-Coredhcp-Signature"))
	assert.Equal(t, "application/json", p.header.Get("Content-Type"))

	var ev struct {
		Family       int      `json:"family"`
		Event        string   `json:"event"`
		Time         string   `json:"time"`
		MAC          string   `json:"mac"`
		Hostname     string   `json:"hostname"`
		Addresses    []string `json:"addresses"`
		LeaseSeconds int64    `json:"lease_seconds"`
	}
	require.NoError(t, json.Unmarshal(p.body, &ev))
	assert.Equal(t, 4, ev.Family)
	assert.Equal(t, "ack", ev.Event)
	assert.Equal(t, testMAC.String(), ev.MAC)
	assert.Equal(t, "laptop", ev.Hostname)
	assert.Equal(t, []string{"10.0.0.5/32"}, ev.Addresses)
	assert.Equal(t, int64(3600), ev.LeaseSeconds)

	stamped, err := time.Parse(time.RFC3339, ev.Time)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), stamped, time.Minute)

	// Outside the "events:ack" allow-list configured above, so nothing is posted.
	offer, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(net.IPv4(10, 0, 0, 5)),
	)
	require.NoError(t, err)
	handle(req, offer)
	assert.Empty(t, got)
}

func TestSetup6ReportsAReply(t *testing.T) {
	srv, got := newEndpoint(t)
	handle, err := leasehook.Plugin.Setup6("url:" + srv.URL)
	require.NoError(t, err)
	require.NotNil(t, handle)

	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRequest

	resp, err := dhcpv6.NewMessage(dhcpv6.WithIANA(dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2001:db8::5"),
		PreferredLifetime: 30 * time.Minute,
		ValidLifetime:     time.Hour,
	}))
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	out, stop := handle(req, resp)
	assert.Same(t, resp, out)
	assert.False(t, stop)

	p := await(t, got)
	assert.Empty(t, p.header.Get("X-Coredhcp-Signature"), "no secret was configured")

	var ev struct {
		Family       int      `json:"family"`
		Event        string   `json:"event"`
		MAC          string   `json:"mac"`
		DUID         string   `json:"duid"`
		Addresses    []string `json:"addresses"`
		LeaseSeconds int64    `json:"lease_seconds"`
	}
	require.NoError(t, json.Unmarshal(p.body, &ev))
	assert.Equal(t, 6, ev.Family)
	assert.Equal(t, "reply", ev.Event)
	assert.Equal(t, testMAC.String(), ev.MAC)
	assert.Equal(t, hex.EncodeToString(duid.ToBytes()), ev.DUID)
	assert.Equal(t, []string{"2001:db8::5/128"}, ev.Addresses)
	assert.Equal(t, int64(3600), ev.LeaseSeconds)
}
