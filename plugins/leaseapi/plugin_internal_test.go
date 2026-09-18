// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leaseapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/plugins/internal/endpoint"
)

// ResetRegistry stops every listener started so far and empties the
// package-level registry, immediately and again when the test finishes.
//
// It is exported from a _test.go file rather than from plugin.go on purpose:
// the black-box test package needs it to keep tests independent of each other,
// while shipped code has no way to stop the API listener at all. See the
// comment on the serve goroutine in newServer for why.
func ResetRegistry(t *testing.T) {
	t.Helper()
	resetRegistry()
	t.Cleanup(resetRegistry)
}

func resetRegistry() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for key, s := range registry.servers {
		_ = s.srv.Close()
		// Serve has to have returned before the address is free for the next
		// test; waiting on done is how we avoid a sleep here.
		<-s.done
		delete(registry.servers, key)
	}
}

// SetStreamThreshold lowers the entry count above which a response is streamed
// instead of buffered, and restores it when the test finishes.
//
// It is exported for the black-box tests, which would otherwise have to build
// a hundred thousand leases to reach the streaming path. The threshold that
// ships is asserted in TestStreamThresholdDefault.
func SetStreamThreshold(t *testing.T, n int) {
	t.Helper()
	previous := streamThreshold
	streamThreshold = n
	t.Cleanup(func() { streamThreshold = previous })
}

// socketPath returns a path for a unix socket in a directory of its own.
//
// It does not use t.TempDir: that names the directory after the test, and a
// unix socket path is limited to 104 bytes on darwin and 108 on Linux, which a
// long subtest name under /var/folders reaches on its own.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cdhcp") //nolint:usetesting // t.TempDir() path is too long for a unix socket
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")
	require.Less(t, len(path), 100, "test setup: socket path is too long to bind")
	return path
}

func TestStreamThresholdDefault(t *testing.T) {
	assert.Equal(t, 100_000, streamThreshold)
}

func TestServeLoopLogsAListenerFailure(t *testing.T) {
	ResetRegistry(t)
	e, err := endpoint.Parse(pluginName, []string{"tcp:127.0.0.1:0"})
	require.NoError(t, err)
	s, err := newServer(e)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.srv.Close() })

	// Closing the listener out from under Serve makes it return something
	// other than ErrServerClosed, which is the branch that logs.
	require.NoError(t, s.ln.Close())
	<-s.done
}

// stub is a Source built from fixed data.
type stub struct {
	name   string
	leases []leases.Lease
	pools  []leases.Pool
}

func (s *stub) Name() string           { return s.name }
func (s *stub) Leases() []leases.Lease { return s.leases }
func (s *stub) Pools() []leases.Pool   { return s.pools }

// register adds a source for the duration of the test.
func register(t *testing.T, s leases.Source) {
	t.Helper()
	leases.Register(s)
	t.Cleanup(func() { leases.Unregister(s) })
}

func TestParseFilter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		query   string
		want    filter
		wantErr error
	}{
		{name: "no filter", query: ""},
		{name: "family 4", query: "family=4", want: filter{family: 4}},
		{name: "family 6", query: "family=6", want: filter{family: 6}},
		{
			name:  "a known source",
			query: "source=range+leases.sqlite3",
			want:  filter{source: "range leases.sqlite3", bySource: true},
		},
		{
			name:  "both",
			query: "family=4&source=range+leases.sqlite3",
			want:  filter{family: 4, source: "range leases.sqlite3", bySource: true},
		},
		{name: "an unknown parameter", query: "familly=4", wantErr: ErrUnknownParameter},
		{name: "a family that is not a family", query: "family=5", wantErr: ErrUnknownFamily},
		{name: "an empty family", query: "family=", wantErr: ErrUnknownFamily},
		{name: "a family with padding", query: "family=+4", wantErr: ErrUnknownFamily},
		{name: "an unknown source", query: "source=range+other.sqlite3", wantErr: ErrUnknownSource},
		{name: "an empty source", query: "source=", wantErr: ErrUnknownSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			register(t, &stub{name: "range leases.sqlite3"})
			q, err := url.ParseQuery(tc.query)
			require.NoError(t, err)

			got, err := parseFilter(q)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Equal(t, filter{}, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// failingWriter fails the nth write and every one after it.
type failingWriter struct {
	failAfter int
	writes    int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("connection reset")
	}
	return len(p), nil
}

func TestEncodeListWriteFailures(t *testing.T) {
	items := []leases.Lease{
		{Family: 4, Client: "a", Address: netip.MustParsePrefix("10.0.0.1/32")},
		{Family: 4, Client: "b", Address: netip.MustParsePrefix("10.0.0.2/32")},
	}

	// Four writes make up a two-entry body: the opening brace, the first
	// entry, the separator, the second entry, and the closing bracket. Each
	// failure point has to come back as an error rather than a short body.
	for failAfter := range 5 {
		t.Run("fails after "+string(rune('0'+failAfter))+" writes", func(t *testing.T) {
			err := encodeList(&failingWriter{failAfter: failAfter}, "leases", items)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "connection reset")
		})
	}

	t.Run("all writes succeed", func(t *testing.T) {
		assert.NoError(t, encodeList(&failingWriter{failAfter: 99}, "leases", items))
	})
}

// failingResponseWriter is an http.ResponseWriter whose body writes always
// fail, which is what a client hanging up mid-response looks like.
type failingResponseWriter struct {
	header http.Header
	status int
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

func (f *failingResponseWriter) WriteHeader(status int) { f.status = status }

func TestRespondWriteFailures(t *testing.T) {
	items := []leases.Lease{
		{Family: 4, Client: "a", Address: netip.MustParsePrefix("10.0.0.1/32")},
		{Family: 4, Client: "b", Address: netip.MustParsePrefix("10.0.0.2/32")},
	}

	t.Run("buffered", func(t *testing.T) {
		w := &failingResponseWriter{}
		respond(w, "leases", items)
		assert.Equal(t, contentType, w.Header().Get("Content-Type"))
	})

	t.Run("streamed", func(t *testing.T) {
		SetStreamThreshold(t, 1)
		w := &failingResponseWriter{}
		respond(w, "leases", items)
		assert.Equal(t, contentType, w.Header().Get("Content-Type"))
	})
}

func TestBadRequestWriteFailure(t *testing.T) {
	w := &failingResponseWriter{}
	r := httptest.NewRequest(http.MethodGet, "/v1/leases?family=9", nil)

	badRequest(w, r, ErrUnknownFamily)

	assert.Equal(t, http.StatusBadRequest, w.status)
	assert.Equal(t, contentType, w.Header().Get("Content-Type"))
}

func TestServeHealthWriteFailure(t *testing.T) {
	w := &failingResponseWriter{}
	serveHealth(w, httptest.NewRequest(http.MethodGet, "/v1/health", nil))

	assert.Equal(t, contentType, w.Header().Get("Content-Type"))
}

func TestWriteJSONEncodeFailure(t *testing.T) {
	// No type this package hands the encoder can fail on, so the failure is
	// injected here instead.
	w := httptest.NewRecorder()

	writeJSON(w, http.StatusOK, func(out io.Writer) error {
		_, _ = io.WriteString(out, `{"leases":[`)
		return errors.New("marshalling a lease")
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "leases", "a half-encoded body never reaches the client")
}

func TestHandlersPassThrough(t *testing.T) {
	s := &server{}

	resp4, stop4 := s.Handler4(nil, nil)
	assert.Nil(t, resp4)
	assert.False(t, stop4)

	resp6, stop6 := s.Handler6(nil, nil)
	assert.Nil(t, resp6)
	assert.False(t, stop6)
}

func TestSetupReturnsTheSameServerForOneAddress(t *testing.T) {
	ResetRegistry(t)
	path := socketPath(t)

	first, err := setup([]string{"unix:" + path})
	require.NoError(t, err)
	second, err := setup([]string{"unix:" + path, "mode:0660"})
	require.NoError(t, err)

	// The mode of the second setup is ignored along with everything else
	// about it: the address is the key, and the listener is already up.
	assert.Same(t, first, second)
	assert.Len(t, registry.servers, 1)
}
