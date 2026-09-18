// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package endpoint_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/internal/endpoint"
)

// tempSocket returns a path for a unix socket in a directory of its own,
// short enough for the 104 byte limit darwin puts on a socket path.
func tempSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "a.sock")
}

func TestParseRefusesARoutableAddress(t *testing.T) {
	// The whole point of the package: a plugin serving something
	// unauthenticated may not be talked into binding an address the rest of
	// the network can reach, whichever plugin asks.
	for _, tc := range []struct {
		name string
		args []string
		opts []endpoint.Option
	}{
		{name: "a routable literal", args: []string{"tcp:192.0.2.1:9755"}},
		{name: "the wildcard address", args: []string{"tcp:0.0.0.0:9755"}},
		{name: "a port on its own", args: []string{"tcp::9755"}},
		{name: "a name that may resolve anywhere", args: []string{"tcp:localhost:9755"}},
		{name: "a bare routable literal", args: []string{"192.0.2.1:9754"}, opts: []endpoint.Option{endpoint.AllowBareTCP()}},
		{name: "a bare port on its own", args: []string{":9754"}, opts: []endpoint.Option{endpoint.AllowBareTCP()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := endpoint.Parse("someplugin", tc.args, tc.opts...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a loopback address")
			assert.Contains(t, err.Error(), "unauthenticated")
		})
	}
}

func TestListenTCP(t *testing.T) {
	e, err := endpoint.Parse("someplugin", []string{"tcp:127.0.0.1:0"})
	require.NoError(t, err)
	assert.Equal(t, "tcp:127.0.0.1:0", e.Key())
	assert.Equal(t, "loopback only", e.Guard())

	ln, err := e.Listen(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	assert.Equal(t, "tcp", ln.Addr().Network())
	// Port 0 asked the kernel for a free port, so the bound address is not
	// the configured one and the caller has to read it off the listener.
	assert.NotEqual(t, "127.0.0.1:0", ln.Addr().String())
}

func TestListenTCPOnATakenPort(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })

	e, err := endpoint.Parse("someplugin", []string{"tcp:" + taken.Addr().String()})
	require.NoError(t, err)

	_, err = e.Listen(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "someplugin: cannot listen on")
}

func TestListenUnix(t *testing.T) {
	path := tempSocket(t)
	e, err := endpoint.Parse("someplugin", []string{"unix:" + path, "mode:0660"})
	require.NoError(t, err)
	assert.Equal(t, "unix:"+path, e.Key())
	assert.Equal(t, "socket mode 0660", e.Guard())

	ln, err := e.Listen(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o660), info.Mode().Perm())
	assert.NotZero(t, info.Mode()&os.ModeSocket)
}

func TestListenUnixDefaultsToOwnerOnly(t *testing.T) {
	path := tempSocket(t)
	e, err := endpoint.Parse("someplugin", []string{"unix:" + path})
	require.NoError(t, err)

	ln, err := e.Listen(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the socket permissions are the authentication, so the default has to be the closed one")
}
