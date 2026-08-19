// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func macPageBody(t *testing.T, entries ...macAddress) []byte {
	t.Helper()
	return mustJSON(t, macAddressPage{Results: entries})
}

func ipPageBody(t *testing.T, addrs ...string) []byte {
	t.Helper()
	results := make([]ipAddress, len(addrs))
	for i, a := range addrs {
		results[i] = ipAddress{Address: a}
	}
	return mustJSON(t, ipAddressPage{Results: results})
}

// checkRequest fails the test (via t.Errorf, so it is safe to call from the
// server's own goroutine) when r does not match what the plugin is
// documented to send.
func checkRequest(t *testing.T, r *http.Request, wantPath string, wantQuery url.Values, wantAuth string) {
	t.Helper()
	if r.URL.Path != wantPath {
		t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
	}
	if got := r.URL.Query().Encode(); got != wantQuery.Encode() {
		t.Errorf("query = %q, want %q", got, wantQuery.Encode())
	}
	if got := r.Header.Get("Authorization"); got != wantAuth {
		t.Errorf("Authorization = %q, want %q", got, wantAuth)
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want %q", got, "application/json")
	}
}

func TestParseBaseURL(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		want        string
		wantErrText string
	}{
		{name: "plain https host", raw: "https://netbox.example.com", want: "https://netbox.example.com"},
		{name: "http host", raw: "http://netbox.example.com", want: "http://netbox.example.com"},
		{name: "host with a subpath", raw: "https://netbox.example.com/netbox", want: "https://netbox.example.com/netbox"},
		{name: "trailing slash stripped", raw: "https://netbox.example.com/", want: "https://netbox.example.com"},
		{name: "subpath with trailing slash stripped", raw: "https://netbox.example.com/netbox/", want: "https://netbox.example.com/netbox"},
		{name: "empty string errors", raw: "", wantErrText: "scheme must be http or https"},
		{name: "scheme is not http or https", raw: "ftp://host", wantErrText: "scheme must be http or https"},
		{name: "missing scheme entirely", raw: "netbox.example.com", wantErrText: "scheme must be http or https"},
		{name: "missing host", raw: "https://", wantErrText: "missing host"},
		{name: "URL carrying a query", raw: "https://h/?a=b", wantErrText: "query or fragment"},
		{name: "URL carrying a fragment", raw: "https://h/#f", wantErrText: "query or fragment"},
		{name: "syntactically invalid URL", raw: "http://%zz", wantErrText: "invalid NetBox URL"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBaseURL(tc.raw)
			if tc.wantErrText != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveToken(t *testing.T) {
	cases := []struct {
		name        string
		arg         string
		setup       func(t *testing.T)
		want        string
		wantErrText string
	}{
		{
			name: "a literal token passes through",
			arg:  "plain-token",
			want: "plain-token",
		},
		{
			name:        "an empty string errors",
			arg:         "",
			wantErrText: "cannot be empty",
		},
		{
			name:        "env: with no name errors",
			arg:         "env:",
			wantErrText: "needs an environment variable name",
		},
		{
			name: "env:NAME with the variable unset errors",
			arg:  "env:NETBOX_TEST_TOKEN_UNSET",
			setup: func(t *testing.T) {
				t.Helper()
				require.NoError(t, os.Unsetenv("NETBOX_TEST_TOKEN_UNSET"))
			},
			wantErrText: "unset or empty",
		},
		{
			name: "env:NAME set to empty errors",
			arg:  "env:NETBOX_TEST_TOKEN_EMPTY",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("NETBOX_TEST_TOKEN_EMPTY", "")
			},
			wantErrText: "unset or empty",
		},
		{
			name: "env:NAME set to a value returns that value",
			arg:  "env:NETBOX_TEST_TOKEN_VALUE",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("NETBOX_TEST_TOKEN_VALUE", "secret123")
			},
			want: "secret123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			got, err := resolveToken(tc.arg)
			if tc.wantErrText != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAuthHeader(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{name: "v2 token gets the Bearer scheme", token: "nbt_x", want: "Bearer nbt_x"},
		{name: "legacy token gets the Token scheme", token: "x", want: "Token x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, authHeader(tc.token))
		})
	}
}

func TestLookupDeviceInterface(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   123,
		AssignedObject: &assignedObject{
			Name:   "eth0",
			Device: &namedObject{Name: "sw1"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			checkRequest(t, r, macAddressPath, url.Values{
				"mac_address": {"aa:bb:cc:dd:ee:ff"},
				"limit":       {"10"},
			}, "Token secret")
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			checkRequest(t, r, ipAddressPath, url.Values{
				"interface_id": {"123"},
				"status":       {"active"},
				"limit":        {"20"},
			}, "Token secret")
			_, _ = w.Write(ipPageBody(t, "10.0.0.5/24", "2001:db8::5/64"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.5/24"), result.v4)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::5/64"), result.v6)
}

func TestLookupVMInterface(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeVMInterface,
		AssignedObjectID:   456,
		AssignedObject: &assignedObject{
			Name:           "eth0",
			VirtualMachine: &namedObject{Name: "vm1"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			checkRequest(t, r, macAddressPath, url.Values{
				"mac_address": {"aa:bb:cc:dd:ee:ff"},
				"limit":       {"10"},
			}, "Bearer nbt_secret")
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			checkRequest(t, r, ipAddressPath, url.Values{
				"vminterface_id": {"456"},
				"status":         {"active"},
				"limit":          {"20"},
			}, "Bearer nbt_secret")
			_, _ = w.Write(ipPageBody(t, "10.0.0.5/24", "2001:db8::5/64"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "nbt_secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.5/24"), result.v4)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::5/64"), result.v6)
}

func TestLookupMACNotFound(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		checkRequest(t, r, macAddressPath, url.Values{
			"mac_address": {"aa:bb:cc:dd:ee:ff"},
			"limit":       {"10"},
		}, "Token secret")
		_, _ = w.Write(macPageBody(t))
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.False(t, result.found)
	assert.Equal(t, int32(1), calls.Load(), "a MAC NetBox does not know must not trigger the address lookup")
}

func TestLookupSkipsUnusableEntriesUntilAssignedOne(t *testing.T) {
	unassigned := macAddress{}
	frontport := macAddress{
		AssignedObjectType: "dcim.frontport",
		AssignedObjectID:   9,
		AssignedObject:     &assignedObject{Name: "fp"},
	}
	zeroID := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   0,
		AssignedObject:     &assignedObject{Name: "x"},
	}
	usable := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   42,
		AssignedObject: &assignedObject{
			Name:   "eth1",
			Device: &namedObject{Name: "sw2"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			_, _ = w.Write(macPageBody(t, unassigned, frontport, zeroID, usable))
		case ipAddressPath:
			checkRequest(t, r, ipAddressPath, url.Values{
				"interface_id": {"42"},
				"status":       {"active"},
				"limit":        {"20"},
			}, "Token secret")
			_, _ = w.Write(ipPageBody(t, "10.0.0.1/24"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.1/24"), result.v4)
}

func TestLookupNothingUsable(t *testing.T) {
	var calls atomic.Int32
	unassigned := macAddress{}
	frontport := macAddress{
		AssignedObjectType: "dcim.frontport",
		AssignedObjectID:   9,
		AssignedObject:     &assignedObject{Name: "fp"},
	}
	zeroID := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObject:     &assignedObject{Name: "x"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write(macPageBody(t, unassigned, frontport, zeroID))
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.False(t, result.found)
	assert.Equal(t, int32(1), calls.Load())
}

func TestLookupFirstAddressPerFamilyWins(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   77,
		AssignedObject:     &assignedObject{Name: "eth0", Device: &namedObject{Name: "sw1"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			_, _ = w.Write(ipPageBody(t, "10.0.0.1/24", "10.0.0.2/24", "2001:db8::1/64", "2001:db8::2/64"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.1/24"), result.v4)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::1/64"), result.v6)
}

func TestLookupUnparseableAddressSkipped(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   1,
		AssignedObject:     &assignedObject{Name: "eth0", Device: &namedObject{Name: "sw1"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			_, _ = w.Write(ipPageBody(t, "not-an-address", "10.0.0.9/24"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.9/24"), result.v4)
	assert.False(t, result.v6.IsValid())
}

func TestLookupNoAddresses(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   1,
		AssignedObject:     &assignedObject{Name: "eth0", Device: &namedObject{Name: "sw1"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			_, _ = w.Write(ipPageBody(t))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
	assert.False(t, result.v4.IsValid())
	assert.False(t, result.v6.IsValid())
}

func TestLookupHTTPErrors(t *testing.T) {
	okMAC := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   1,
		AssignedObject:     &assignedObject{Name: "eth0", Device: &namedObject{Name: "sw1"}},
	}

	cases := []struct {
		name      string
		macStatus int
		ipStatus  int
		wantToken bool
	}{
		{name: "401 on the MAC call names the token", macStatus: http.StatusUnauthorized, wantToken: true},
		{name: "403 on the MAC call names the token", macStatus: http.StatusForbidden, wantToken: true},
		{name: "500 on the MAC call omits the token", macStatus: http.StatusInternalServerError, wantToken: false},
		{name: "500 on the IP address call", ipStatus: http.StatusInternalServerError, wantToken: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case macAddressPath:
					if tc.macStatus != 0 {
						w.WriteHeader(tc.macStatus)
						return
					}
					_, _ = w.Write(macPageBody(t, okMAC))
				case ipAddressPath:
					if tc.ipStatus != 0 {
						w.WriteHeader(tc.ipStatus)
						return
					}
					_, _ = w.Write(ipPageBody(t, "10.0.0.1/24"))
				}
			}))
			defer srv.Close()

			c := newClient(srv.URL, "secret", time.Second)
			_, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
			require.Error(t, err)
			assert.Equal(t, tc.wantToken, strings.Contains(err.Error(), "token"))
		})
	}
}

func TestLookupMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":`))
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	_, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding")
}

func TestLookupOversizedBody(t *testing.T) {
	// The content does not need to be valid JSON: the size check runs before
	// decoding, so a body over the limit fails there regardless of shape.
	body := []byte(strings.Repeat("a", maxBodyBytes+1))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	_, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "larger than")
}

func TestLookupTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write(macPageBody(t))
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", 20*time.Millisecond)
	_, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	assert.Error(t, err)
}

func TestLookupTransportError(t *testing.T) {
	// A server that is already closed makes the transport itself fail,
	// rather than the request being answered with an error status.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	_, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.Error(t, err)
	assert.Contains(t, err.Error(), macAddressPath)
}

func TestGetRequestBuildFailure(t *testing.T) {
	// A control character in the base URL makes http.NewRequestWithContext
	// itself fail, which parseBaseURL would normally have caught first; this
	// bypasses it by constructing the client directly.
	c := &client{
		base: "http://exa\x7fmple.com",
		auth: authHeader("secret"),
		hc:   &http.Client{},
	}

	var out macAddressPage
	err := c.get(context.Background(), macAddressPath, url.Values{}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "building request")
}

// errReadCloser is an io.ReadCloser whose Read always fails with something
// other than io.EOF, to exercise the io.ReadAll error path in c.get.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }
func (errReadCloser) Close() error             { return nil }

// stubTransport hands back a 200 response whose body cannot be read, without
// touching the network at all.
type stubTransport struct{}

func (stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       errReadCloser{},
		Header:     make(http.Header),
	}, nil
}

func TestGetReadFailure(t *testing.T) {
	c := &client{
		base: "http://example.com",
		auth: authHeader("secret"),
		hc:   &http.Client{Transport: stubTransport{}},
	}

	var out macAddressPage
	err := c.get(context.Background(), macAddressPath, url.Values{}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading response")
}

func TestInterfaceRefString(t *testing.T) {
	r := interfaceRef{name: "eth0", parent: "sw1"}
	assert.Equal(t, "eth0 on sw1", r.String())
}

func TestLookupParentNameFallback(t *testing.T) {
	mac := macAddress{
		AssignedObjectType: objectTypeInterface,
		AssignedObjectID:   1,
		AssignedObject:     &assignedObject{Name: "eth0"}, // neither device nor virtual_machine set
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case macAddressPath:
			_, _ = w.Write(macPageBody(t, mac))
		case ipAddressPath:
			_, _ = w.Write(ipPageBody(t, "10.0.0.1/24"))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL, "secret", time.Second)
	// parentName only feeds a log line; the lookup itself must still succeed
	// when the response has neither a device nor a virtual machine.
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.True(t, result.found)
}

func TestLookupBaseURLWithSubpath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/netbox/api/dcim/mac-addresses/" {
			t.Errorf("path = %q, want %q", r.URL.Path, "/netbox/api/dcim/mac-addresses/")
		}
		_, _ = w.Write(macPageBody(t))
	}))
	defer srv.Close()

	c := newClient(srv.URL+"/netbox", "secret", time.Second)
	result, err := c.lookup(context.Background(), "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.False(t, result.found)
}
