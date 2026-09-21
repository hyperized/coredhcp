// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package endpoint

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPlugin = "someplugin"

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

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		opts    []Option
		want    Endpoint
		wantErr string
	}{
		{
			name: "unix socket with the default mode",
			args: []string{"unix:/run/coredhcp/api.sock"},
			want: Endpoint{plugin: testPlugin, network: "unix", address: "/run/coredhcp/api.sock", mode: 0o600},
		},
		{
			name: "unix socket with a mode",
			args: []string{"unix:/run/coredhcp/api.sock", "mode:0660"},
			want: Endpoint{plugin: testPlugin, network: "unix", address: "/run/coredhcp/api.sock", mode: 0o660},
		},
		{
			name: "a mode without a leading zero",
			args: []string{"unix:/tmp/a.sock", "mode:660"},
			want: Endpoint{plugin: testPlugin, network: "unix", address: "/tmp/a.sock", mode: 0o660},
		},
		{
			name: "surrounding space is ignored",
			args: []string{" unix:/tmp/a.sock ", " mode:0660 "},
			want: Endpoint{plugin: testPlugin, network: "unix", address: "/tmp/a.sock", mode: 0o660},
		},
		{
			name: "loopback tcp",
			args: []string{"tcp:127.0.0.1:9755"},
			want: Endpoint{plugin: testPlugin, network: "tcp", address: "127.0.0.1:9755"},
		},
		{
			name: "loopback tcp elsewhere in 127/8",
			args: []string{"tcp:127.7.7.7:9755"},
			want: Endpoint{plugin: testPlugin, network: "tcp", address: "127.7.7.7:9755"},
		},
		{
			name: "loopback tcp over IPv6",
			args: []string{"tcp:[::1]:9755"},
			want: Endpoint{plugin: testPlugin, network: "tcp", address: "[::1]:9755"},
		},
		{
			name: "a bare address is tcp when the plugin allows it",
			args: []string{"127.0.0.1:9754"},
			opts: []Option{AllowBareTCP()},
			want: Endpoint{plugin: testPlugin, network: "tcp", address: "127.0.0.1:9754"},
		},
		{
			name: "a bare IPv6 address keeps its brackets",
			args: []string{"[::1]:9754"},
			opts: []Option{AllowBareTCP()},
			want: Endpoint{plugin: testPlugin, network: "tcp", address: "[::1]:9754"},
		},
		{
			name: "a scheme still wins over the bare form",
			args: []string{"unix:/tmp/a.sock", "mode:0660"},
			opts: []Option{AllowBareTCP()},
			want: Endpoint{plugin: testPlugin, network: "unix", address: "/tmp/a.sock", mode: 0o660},
		},
		{name: "no arguments", args: nil, wantErr: "expected one or two arguments"},
		{
			name:    "too many arguments",
			args:    []string{"unix:/tmp/a.sock", "mode:0660", "extra"},
			wantErr: "expected one or two arguments",
		},
		{name: "no scheme", args: []string{"/tmp/a.sock"}, wantErr: "invalid address"},
		{name: "unknown scheme", args: []string{"udp:127.0.0.1:9755"}, wantErr: "unknown address scheme"},
		{name: "empty socket path", args: []string{"unix:"}, wantErr: "path cannot be empty"},
		{name: "mode on a tcp address", args: []string{"tcp:127.0.0.1:9755", "mode:0660"}, wantErr: "applies to a unix socket"},
		{name: "tcp without a port", args: []string{"tcp:127.0.0.1"}, wantErr: "invalid tcp address"},
		{name: "tcp on a routable address", args: []string{"tcp:192.0.2.1:9755"}, wantErr: "not a loopback address"},
		{name: "tcp on the wildcard address", args: []string{"tcp::9755"}, wantErr: "not a loopback address"},
		{name: "tcp on a name", args: []string{"tcp:localhost:9755"}, wantErr: "not a loopback address"},
		{
			name:    "a bare wildcard address is refused too",
			args:    []string{":9754"},
			opts:    []Option{AllowBareTCP()},
			wantErr: "not a loopback address",
		},
		{
			name:    "a bare routable address is refused",
			args:    []string{"0.0.0.0:9754"},
			opts:    []Option{AllowBareTCP()},
			wantErr: "not a loopback address",
		},
		{
			name:    "a bare address with no port",
			args:    []string{"127.0.0.1"},
			opts:    []Option{AllowBareTCP()},
			wantErr: "invalid address",
		},
		{name: "unknown second argument", args: []string{"unix:/tmp/a.sock", "perm:0660"}, wantErr: "unexpected argument"},
		{name: "second argument without a value", args: []string{"unix:/tmp/a.sock", "mode"}, wantErr: "unexpected argument"},
		{name: "mode that is not octal", args: []string{"unix:/tmp/a.sock", "mode:0x1ff"}, wantErr: "invalid mode"},
		{name: "mode of zero", args: []string{"unix:/tmp/a.sock", "mode:0"}, wantErr: "outside 0001-0777"},
		{name: "mode with a bit outside the permissions", args: []string{"unix:/tmp/a.sock", "mode:4755"}, wantErr: "outside 0001-0777"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(testPlugin, tc.args, tc.opts...)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Contains(t, err.Error(), testPlugin, "every error names the plugin it came from")
				assert.Equal(t, Endpoint{}, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSyntaxNamesTheBareForm(t *testing.T) {
	strict := (&parser{}).syntax()
	bare := (&parser{bareTCP: true}).syntax()

	assert.NotContains(t, strict, "bare")
	assert.Contains(t, bare, "bare")
}

func TestKeyAndGuard(t *testing.T) {
	unix := Endpoint{network: "unix", address: "/run/api.sock", mode: 0o660}
	assert.Equal(t, "unix:/run/api.sock", unix.Key())
	assert.Equal(t, "socket mode 0660", unix.Guard())

	tcp := Endpoint{network: "tcp", address: "127.0.0.1:9755"}
	assert.Equal(t, "tcp:127.0.0.1:9755", tcp.Key())
	assert.Equal(t, "loopback only", tcp.Guard())
}

func TestClearStaleSocket(t *testing.T) {
	ctx := t.Context()

	t.Run("nothing there", func(t *testing.T) {
		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: socketPath(t)}
		assert.NoError(t, e.clearStaleSocket(ctx))
	})

	t.Run("a stale socket is removed", func(t *testing.T) {
		path := socketPath(t)
		// Closing a listener normally unlinks its socket. Turning that off
		// leaves the file behind the way a killed process does.
		stale, err := net.Listen("unix", path)
		require.NoError(t, err)
		unixStale, ok := stale.(*net.UnixListener)
		require.True(t, ok, "unix listener must be a *net.UnixListener")
		unixStale.SetUnlinkOnClose(false)
		require.NoError(t, stale.Close())
		require.FileExists(t, path)

		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path}
		require.NoError(t, e.clearStaleSocket(ctx))
		_, err = os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("a live socket is left alone", func(t *testing.T) {
		path := socketPath(t)
		ln, err := net.Listen("unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path}
		err = e.clearStaleSocket(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "something is already listening")
	})

	t.Run("a regular file is left alone", func(t *testing.T) {
		path := socketPath(t)
		require.NoError(t, os.WriteFile(path, []byte("not a socket"), 0o600))

		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path}
		err := e.clearStaleSocket(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a socket")
	})

	t.Run("a path that cannot be inspected", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "f")
		require.NoError(t, os.WriteFile(file, nil, 0o600))

		// A path under a regular file is neither missing nor inspectable.
		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: filepath.Join(file, "a.sock")}
		err := e.clearStaleSocket(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot inspect")
	})
}

func TestListenUnixFailures(t *testing.T) {
	ctx := t.Context()

	t.Run("a path that cannot be bound", func(t *testing.T) {
		e := Endpoint{
			plugin:  testPlugin,
			network: NetworkUnix,
			address: filepath.Join(filepath.Dir(socketPath(t)), "missing", "a.sock"),
			mode:    0o600,
		}

		_, err := e.Listen(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot listen on")
	})

	t.Run("a stale socket that cannot be cleared", func(t *testing.T) {
		path := socketPath(t)
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path, mode: 0o600}

		_, err := e.Listen(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a socket")
	})

	t.Run("a mode that cannot be set", func(t *testing.T) {
		path := socketPath(t)
		chmodFile = func(string, os.FileMode) error { return errors.New("read-only file system") }
		t.Cleanup(func() { chmodFile = os.Chmod })
		e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path, mode: 0o660}

		_, err := e.Listen(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot set mode 0660")

		// The failed Listen closed its listener, so the path is free again.
		ln, err := net.Listen("unix", path)
		require.NoError(t, err)
		require.NoError(t, ln.Close())
	})
}

func TestBindTimeoutIsSane(t *testing.T) {
	// A bind that takes longer than this is the stale-socket probe waiting on
	// a full accept backlog, which is a failure, not a slow start.
	assert.Equal(t, 5*time.Second, bindTimeout)
}

func TestStaleSocketIsKeptWhenTheProbeCannotFinish(t *testing.T) {
	path := socketPath(t)
	// A socket file with nothing listening: the probe would normally fail to
	// connect and the file would be unlinked as stale.
	stale, err := net.Listen("unix", path)
	require.NoError(t, err)
	unixStale, ok := stale.(*net.UnixListener)
	require.True(t, ok, "unix listener must be a *net.UnixListener")
	unixStale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	e := Endpoint{plugin: testPlugin, network: NetworkUnix, address: path, mode: 0o600}
	_, err = e.Listen(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	assert.FileExists(t, path, "a probe that did not finish says nothing about whether the socket is in use")
}
