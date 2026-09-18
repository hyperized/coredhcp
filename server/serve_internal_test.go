// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
)

// testConfig builds a *config.Config with the given v6/v4 listen addresses.
// A nil slice omits that protocol's ServerConfig entirely; a non-nil
// (possibly empty) slice includes it with no plugins configured.
func testConfig(t *testing.T, v6addrs, v4addrs []net.UDPAddr) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	if v6addrs != nil {
		cfg.Server6 = &config.ServerConfig{Addresses: v6addrs}
	}
	if v4addrs != nil {
		cfg.Server4 = &config.ServerConfig{Addresses: v4addrs}
	}
	return cfg
}

// --- test doubles for conn4/conn6, shared with handle_internal_test.go ---

type fakeReadResult4 struct {
	data []byte
	oob  *ipv4.ControlMessage
	peer net.Addr
	err  error
}

type fakeWriteCall4 struct {
	b   []byte
	cm  *ipv4.ControlMessage
	dst net.Addr
}

// fakeConn4 is a test double for conn4 that serves a queue of reads and
// records every write. Not safe for concurrent ReadFrom calls, but WriteTo
// is safe to call from a HandleMsg4 goroutine while the test goroutine reads
// back through writeCh.
type fakeConn4 struct {
	reads    []fakeReadResult4
	readIdx  int
	writeErr error
	writes   []fakeWriteCall4
	writeCh  chan struct{}
	local    net.Addr
	closeErr error
}

func (f *fakeConn4) ReadFrom(b []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	if f.readIdx >= len(f.reads) {
		return 0, nil, nil, errors.New("fakeConn4: no more queued reads")
	}
	r := f.reads[f.readIdx]
	f.readIdx++
	if r.err != nil {
		return 0, nil, nil, r.err
	}
	n := copy(b, r.data)
	return n, r.oob, r.peer, nil
}

func (f *fakeConn4) WriteTo(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	cp := append([]byte(nil), b...)
	f.writes = append(f.writes, fakeWriteCall4{b: cp, cm: cm, dst: dst})
	err := f.writeErr
	if f.writeCh != nil {
		f.writeCh <- struct{}{}
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *fakeConn4) LocalAddr() net.Addr {
	if f.local != nil {
		return f.local
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 67}
}

func (f *fakeConn4) Close() error { return f.closeErr }

type fakeReadResult6 struct {
	data []byte
	oob  *ipv6.ControlMessage
	peer net.Addr
	err  error
}

type fakeWriteCall6 struct {
	b   []byte
	cm  *ipv6.ControlMessage
	dst net.Addr
}

// fakeConn6 mirrors fakeConn4 for the conn6 interface.
type fakeConn6 struct {
	reads    []fakeReadResult6
	readIdx  int
	writeErr error
	writes   []fakeWriteCall6
	writeCh  chan struct{}
	local    net.Addr
	closeErr error
}

func (f *fakeConn6) ReadFrom(b []byte) (int, *ipv6.ControlMessage, net.Addr, error) {
	if f.readIdx >= len(f.reads) {
		return 0, nil, nil, errors.New("fakeConn6: no more queued reads")
	}
	r := f.reads[f.readIdx]
	f.readIdx++
	if r.err != nil {
		return 0, nil, nil, r.err
	}
	n := copy(b, r.data)
	return n, r.oob, r.peer, nil
}

func (f *fakeConn6) WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error) {
	cp := append([]byte(nil), b...)
	f.writes = append(f.writes, fakeWriteCall6{b: cp, cm: cm, dst: dst})
	err := f.writeErr
	if f.writeCh != nil {
		f.writeCh <- struct{}{}
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *fakeConn6) LocalAddr() net.Addr {
	if f.local != nil {
		return f.local
	}
	return &net.UDPAddr{IP: net.IPv6zero, Port: 547}
}

func (f *fakeConn6) Close() error { return f.closeErr }

// loopbackInterfaceName returns the name of a loopback interface on this
// host, skipping the test if none is found.
func loopbackInterfaceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface found on this host")
	return ""
}

// withNewUDP4 swaps the newUDP4 package var for the duration of the test.
func withNewUDP4(t *testing.T, fn func(string, *net.UDPAddr) (net.PacketConn, error)) {
	t.Helper()
	orig := newUDP4
	newUDP4 = fn
	t.Cleanup(func() { newUDP4 = orig })
}

// withNewUDP6 swaps the newUDP6 package var for the duration of the test.
func withNewUDP6(t *testing.T, fn func(string, *net.UDPAddr) (net.PacketConn, error)) {
	t.Helper()
	orig := newUDP6
	newUDP6 = fn
	t.Cleanup(func() { newUDP6 = orig })
}

// openUDPConn binds a socket and closes it when the test ends.
func openUDPConn(t *testing.T, network string, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedUDPConn returns an already-closed *net.UDPConn suitable as a
// newUDP4/newUDP6 stand-in to drive SetControlMessage/JoinGroup failures.
func closedUDPConn(t *testing.T, network string, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, addr)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	return c
}

// asListener4 unwraps a listener into its *listener4 concrete type. A few
// fields (observer, gate, relayChecked) are only reachable this way, since
// Servers.listeners holds the listener interface.
func asListener4(t *testing.T, l listener) *listener4 {
	t.Helper()
	l4, ok := l.(*listener4)
	require.True(t, ok, "listener is not a *listener4: %T", l)
	return l4
}

// asListener6 mirrors asListener4 for the DHCPv6 side.
func asListener6(t *testing.T, l listener) *listener6 {
	t.Helper()
	l6, ok := l.(*listener6)
	require.True(t, ok, "listener is not a *listener6: %T", l)
	return l6
}

// countingConn is a socket that counts how often it was closed, so a test can
// tell a leak from a close and a close from a double close. It embeds the
// real *net.UDPConn because golang.org/x/net/ipv4.NewPacketConn asserts its
// argument to net.Conn, and because the setup calls listen4 makes have to
// reach a genuine socket to succeed or fail for the right reason.
//
// listen4 and listen6 are synchronous, so the counter needs no lock.
type countingConn struct {
	*net.UDPConn
	closes int
}

func (c *countingConn) Close() error {
	c.closes++
	// The underlying socket is deliberately already closed in most of these
	// tests, so this error is expected and not the counter's business.
	_ = c.UDPConn.Close()
	return nil
}

// The wrappers around the dhcp library's constructors exist to keep a failed
// bind from arriving as a typed nil pointer inside a non-nil net.PacketConn,
// which every later nil check would wave through. A zone naming an interface
// that does not exist fails the same way on every platform.
func TestNewUDPConnWrappersReturnANilInterfaceOnFailure(t *testing.T) {
	const zone = "nonexistent-zzz-iface"

	// assert.Nil is not the check to use here: it reaches through the
	// interface with reflection and passes for a typed nil pointer too,
	// which is the very thing these wrappers exist to prevent. Comparing
	// against a bare nil looks at the interface value itself.
	t.Run("v4", func(t *testing.T) {
		c, err := newIPv4UDPConn(zone, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: zone})
		require.Error(t, err)
		//nolint:testifylint // assert.Nil would pass for a typed nil pointer
		assert.Equal(t, nil, c, "want a nil interface, got %#v", c)
	})

	t.Run("v6", func(t *testing.T) {
		c, err := newIPv6UDPConn(zone, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0, Zone: zone})
		require.Error(t, err)
		//nolint:testifylint // assert.Nil would pass for a typed nil pointer
		assert.Equal(t, nil, c, "want a nil interface, got %#v", c)
	})
}

func TestListen4HappyPath(t *testing.T) {
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	require.NotNil(t, l4)
	defer func() { _ = l4.Close() }()
	assert.NotNil(t, l4.conn4)
}

func TestListen4ConstructorError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return nil, errors.New("constructor boom")
	})
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l4)
	assert.Contains(t, err.Error(), "constructor boom")
}

func TestListen4SetControlMessageError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return closedUDPConn(t, "udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}), nil
	})
	// Zone empty so listen4 takes the SetControlMessage branch.
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l4)
}

func TestListen4ZoneLookupError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return openUDPConn(t, "udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}), nil
	})
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: "nonexistent-zzz-iface"})
	require.Error(t, err)
	assert.Nil(t, l4)
	assert.Contains(t, err.Error(), "could not find interface")
}

func TestListen4JoinGroupError(t *testing.T) {
	iface := loopbackInterfaceName(t)
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return closedUDPConn(t, "udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}), nil
	})
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("224.0.0.1"), Port: 0, Zone: iface})
	require.Error(t, err)
	assert.Nil(t, l4)
}

func TestListen4MulticastJoinGroup(t *testing.T) {
	iface := loopbackInterfaceName(t)
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("224.0.0.1"), Port: 0, Zone: iface})
	if err != nil {
		t.Skipf("multicast join on loopback %q not available on this host: %v", iface, err)
	}
	require.NotNil(t, l4)
	defer func() { _ = l4.Close() }()
	assert.Equal(t, iface, l4.Name)
}

// Every listen4 error path after the bind owns the socket: nothing else holds
// a reference to it, so it has to be closed exactly once before the error goes
// back to the caller. The success path must leave it open, because the
// listener it returns is what closes it later.
func TestListen4ClosesSocketOnlyOnFailure(t *testing.T) {
	iface := loopbackInterfaceName(t)
	local := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	openConn := func(t *testing.T) *countingConn {
		t.Helper()
		return &countingConn{UDPConn: openUDPConn(t, "udp4", &local)}
	}
	// A socket that is already closed makes the setup calls below fail
	// without needing privileges or an unusual host.
	deadConn := func(t *testing.T) *countingConn {
		t.Helper()
		return &countingConn{UDPConn: closedUDPConn(t, "udp4", &local)}
	}

	for _, tc := range []struct {
		name       string
		conn       func(*testing.T) *countingConn
		addr       net.UDPAddr
		wantErr    bool
		wantCloses int
	}{
		{
			name:       "interface lookup fails",
			conn:       openConn,
			addr:       net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: "nonexistent-zzz-iface"},
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "SetControlMessage fails",
			conn:       deadConn,
			addr:       local,
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "JoinGroup fails",
			conn:       deadConn,
			addr:       net.UDPAddr{IP: net.ParseIP("224.0.0.1"), Port: 0, Zone: iface},
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "success keeps the socket for the listener",
			conn:       openConn,
			addr:       local,
			wantErr:    false,
			wantCloses: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := tc.conn(t)
			withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) { return conn, nil })

			l4, err := listen4(&tc.addr)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, l4)
			} else {
				require.NoError(t, err)
				require.NotNil(t, l4)
				defer func() { _ = l4.Close() }()
			}
			assert.Equal(t, tc.wantCloses, conn.closes)
		})
	}
}

func TestListen6HappyPath(t *testing.T) {
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.NoError(t, err)
	require.NotNil(t, l6)
	defer func() { _ = l6.Close() }()
	assert.NotNil(t, l6.conn6)
}

func TestListen6ConstructorError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return nil, errors.New("constructor boom")
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l6)
	assert.Contains(t, err.Error(), "constructor boom")
}

func TestListen6SetControlMessageError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return closedUDPConn(t, "udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}), nil
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l6)
}

func TestListen6ZoneLookupError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return openUDPConn(t, "udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}), nil
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0, Zone: "nonexistent-zzz-iface"})
	require.Error(t, err)
	assert.Nil(t, l6)
	assert.Contains(t, err.Error(), "could not find interface")
}

func TestListen6JoinGroupError(t *testing.T) {
	iface := loopbackInterfaceName(t)
	withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return closedUDPConn(t, "udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}), nil
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 0, Zone: iface})
	require.Error(t, err)
	assert.Nil(t, l6)
}

func TestListen6MulticastJoinGroup(t *testing.T) {
	iface := loopbackInterfaceName(t)
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 0, Zone: iface})
	if err != nil {
		t.Skipf("multicast join on loopback %q not available on this host: %v", iface, err)
	}
	require.NotNil(t, l6)
	defer func() { _ = l6.Close() }()
	assert.Equal(t, iface, l6.Name)
}

// The DHCPv6 half of TestListen4ClosesSocketOnlyOnFailure.
func TestListen6ClosesSocketOnlyOnFailure(t *testing.T) {
	iface := loopbackInterfaceName(t)
	local := net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	openConn := func(t *testing.T) *countingConn {
		t.Helper()
		return &countingConn{UDPConn: openUDPConn(t, "udp6", &local)}
	}
	deadConn := func(t *testing.T) *countingConn {
		t.Helper()
		return &countingConn{UDPConn: closedUDPConn(t, "udp6", &local)}
	}

	for _, tc := range []struct {
		name       string
		conn       func(*testing.T) *countingConn
		addr       net.UDPAddr
		wantErr    bool
		wantCloses int
	}{
		{
			name:       "interface lookup fails",
			conn:       openConn,
			addr:       net.UDPAddr{IP: net.ParseIP("::1"), Port: 0, Zone: "nonexistent-zzz-iface"},
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "SetControlMessage fails",
			conn:       deadConn,
			addr:       local,
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "JoinGroup fails",
			conn:       deadConn,
			addr:       net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 0, Zone: iface},
			wantErr:    true,
			wantCloses: 1,
		},
		{
			name:       "success keeps the socket for the listener",
			conn:       openConn,
			addr:       local,
			wantErr:    false,
			wantCloses: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := tc.conn(t)
			withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) { return conn, nil })

			l6, err := listen6(&tc.addr)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, l6)
			} else {
				require.NoError(t, err)
				require.NotNil(t, l6)
				defer func() { _ = l6.Close() }()
			}
			assert.Equal(t, tc.wantCloses, conn.closes)
		})
	}
}

// A configuration naming no address at all, which `listen: []` produces, is
// refused rather than quietly starting a server with no sockets. Wait on such
// a Servers used to panic in make([]error, 1, 0).
func TestStartWithoutAddresses(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{name: "empty v4 list", cfg: testConfig(t, nil, []net.UDPAddr{})},
		{name: "empty v6 list", cfg: testConfig(t, []net.UDPAddr{}, nil)},
		{name: "both empty", cfg: testConfig(t, []net.UDPAddr{}, []net.UDPAddr{})},
		// A config with neither family never gets this far: LoadChains
		// rejects it first, with its own error.
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := Start(tc.cfg)
			require.ErrorIs(t, err, errNoListeners)
			assert.Nil(t, srv)
		})
	}
}

// Wait has nothing to wait for when no listener was bound, and must neither
// block nor panic. Start does not produce such a Servers any more, but Wait is
// exported and callers can build one.
func TestWaitWithoutListeners(t *testing.T) {
	s := &Servers{}
	assert.NoError(t, s.Wait())
}

// TestStartCleanupJoinsServeGoroutines opens a real DHCPv6 socket and then
// fails the DHCPv4 bind. The v6 read loop has to be finished by the time Start
// returns: with an unbuffered errors channel and no join, cleanup closed the
// socket, Serve returned nil, and the send had nobody to hand it to, leaking
// one goroutine per socket that had already come up.
func TestStartCleanupJoinsServeGoroutines(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return nil, errors.New("v4 listen boom")
	})
	cfg := testConfig(t,
		[]net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
		[]net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)

	before := runtime.NumGoroutine()
	srv, err := Start(cfg)
	require.Error(t, err)
	require.Nil(t, srv)
	// shutdown joins the read loops before returning, so this needs no
	// polling: anything still running here is a leak.
	assert.LessOrEqual(t, runtime.NumGoroutine(), before)
}

// TestStartCleanupOnV6ListenFailure drives Start's cleanup path via
// the DHCPv6 listen loop, with no listeners ever successfully opened.
func TestStartCleanupOnV6ListenFailure(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return nil, errors.New("v6 listen boom")
	})
	cfg := testConfig(t, []net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}}, nil)
	srv, err := Start(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "v6 listen boom")
}

// TestStartCleanupOnV4ListenFailureClosesV6 drives the DHCPv4 listen
// failure branch after a real DHCPv6 listener has already been opened, to
// exercise the cleanup path closing a non-empty listeners slice.
func TestStartCleanupOnV4ListenFailureClosesV6(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (net.PacketConn, error) {
		return nil, errors.New("v4 listen boom")
	})
	cfg := testConfig(t,
		[]net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
		[]net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)
	srv, err := Start(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "v4 listen boom")
}

// Close stays quiet when a listener was already closed (a shutdown signal and
// Wait both close), but still reports genuine close failures.
func TestServersCloseErrorPaths(_ *testing.T) {
	s := &Servers{listeners: []listener{
		&listener4{conn4: &fakeConn4{closeErr: net.ErrClosed}},
		&listener4{conn4: &fakeConn4{closeErr: errors.New("genuinely broken")}},
		nil,
	}}
	// Both paths execute without panicking; the ErrClosed one is silent.
	s.Close()
}

// --- observer reporting at startup ---

// registerTestPlugin registers a plugin for the lifetime of the test and
// removes it again, so the shared registry is left as it was found.
func registerTestPlugin(t *testing.T, plugin *plugins.Plugin) {
	t.Helper()
	require.NoError(t, plugins.RegisterPlugin(plugin))
	t.Cleanup(func() { delete(plugins.RegisteredPlugins, plugin.Name) })
}

// TestStartWithObserverReportsPluginsAndListeners checks the two things the
// observer learns before any packet arrives: which plugins ended up in each
// chain, and which sockets the server bound.
func TestStartWithObserverReportsPluginsAndListeners(t *testing.T) {
	registerTestPlugin(t, &plugins.Plugin{
		Name: "server-observer-test",
		Setup6: func(...string) (handler.Handler6, error) {
			return func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }, nil
		},
		Setup4: func(...string) (handler.Handler4, error) {
			return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }, nil
		},
	})

	cfg := &config.Config{
		Server6: &config.ServerConfig{
			Addresses: []net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
			Plugins:   []config.PluginConfig{{Name: "server-observer-test", Args: []string{"six"}}},
		},
		Server4: &config.ServerConfig{
			Addresses: []net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
			Plugins:   []config.PluginConfig{{Name: "server-observer-test", Args: []string{"four"}}},
		},
	}

	obs := &recordObserver{}
	srv, err := Start(cfg, WithObserver(obs))
	require.NoError(t, err)
	require.NotNil(t, srv)
	srv.Close()
	require.NoError(t, srv.Wait())

	obs.mu.Lock()
	defer obs.mu.Unlock()

	// Plugins come in chain order, DHCPv6 first, matching the order the
	// listeners start in.
	assert.Equal(t, []events.Plugin{
		{Family: events.FamilyV6, Name: "server-observer-test", Args: []string{"six"}},
		{Family: events.FamilyV4, Name: "server-observer-test", Args: []string{"four"}},
	}, obs.plugins)

	require.Len(t, obs.listeners, 2)
	assert.Equal(t, events.FamilyV6, obs.listeners[0].Family)
	assert.Equal(t, events.FamilyV4, obs.listeners[1].Family)
	for _, l := range obs.listeners {
		host, port, err := net.SplitHostPort(l.Address)
		require.NoError(t, err, "listener address %q", l.Address)
		assert.True(t, net.ParseIP(host).IsLoopback(), "listener address %q", l.Address)
		assert.NotEqual(t, "0", port, "the reported port is the one the socket actually got")
		// The configured addresses carry no zone, so no interface is named.
		assert.Empty(t, l.Interface)
	}
}

// The listeners carry the observer down to the packet path, and without
// WithObserver they carry nothing.
func TestStartPassesObserverToListeners(t *testing.T) {
	cfg := testConfig(t,
		[]net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
		[]net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)

	obs := &recordObserver{}
	srv, err := Start(cfg, WithObserver(obs))
	require.NoError(t, err)
	require.Len(t, srv.listeners, 2)
	assert.Same(t, obs, asListener6(t, srv.listeners[0]).observer)
	assert.Same(t, obs, asListener4(t, srv.listeners[1]).observer)
	srv.Close()
	require.NoError(t, srv.Wait())

	plain, err := Start(cfg)
	require.NoError(t, err)
	require.Len(t, plain.listeners, 2)
	assert.Nil(t, asListener6(t, plain.listeners[0]).observer)
	assert.Nil(t, asListener4(t, plain.listeners[1]).observer)
	plain.Close()
	require.NoError(t, plain.Wait())
}

// Reporting is skipped entirely when nobody is watching.
func TestReportWithoutObserver(t *testing.T) {
	s := &Servers{}
	s.reportPlugins(&plugins.Chains{
		V4: []plugins.Link4{{Name: "four"}},
		V6: []plugins.Link6{{Name: "six"}},
	})
	s.reportListener(events.FamilyV4, &net.UDPAddr{IP: net.IPv4zero, Port: 67}, "eth0")
	assert.Nil(t, s.observer)
}

// The observer gets the plugin arguments with the credential forms replaced:
// the terminal UI puts them on screen, and a plugin argument list is where a
// Redis password or a NetBox token is written. See config.RedactArgs.
func TestReportPluginsRedactsArgs(t *testing.T) {
	obs := &recordObserver{}
	s := &Servers{observer: obs}
	s.reportPlugins(&plugins.Chains{
		V6: []plugins.Link6{{Name: "six", Args: []string{"token:s3cret"}}},
		V4: []plugins.Link4{{Name: "four", Args: []string{"redis://user:hunter2@localhost:6379/0", "255.255.255.0"}}},
	})

	obs.mu.Lock()
	defer obs.mu.Unlock()
	assert.Equal(t, []events.Plugin{
		{Family: events.FamilyV6, Name: "six", Args: []string{"token:***"}},
		{Family: events.FamilyV4, Name: "four", Args: []string{"redis://user:***@localhost:6379/0", "255.255.255.0"}},
	}, obs.plugins)
}

// A listener bound to an interface reports it, taken from the zone of the
// configured address.
func TestReportListenerNamesTheInterface(t *testing.T) {
	obs := &recordObserver{}
	s := &Servers{observer: obs}
	s.reportListener(events.FamilyV6, &net.UDPAddr{IP: net.IPv6zero, Port: 547}, "eth0")

	obs.mu.Lock()
	defer obs.mu.Unlock()
	assert.Equal(t, []events.Listener{
		{Family: events.FamilyV6, Address: "[::]:547", Interface: "eth0"},
	}, obs.listeners)
}

// --- shutdown: handlers first, sockets after ---

// closeRecorder is a listener double that only records that it was closed.
// Serve is never called on it: these tests drive shutdown, not traffic.
type closeRecorder struct {
	onClose func()
}

func (c *closeRecorder) Close() error {
	c.onClose()
	return nil
}

func (c *closeRecorder) Serve() error { return nil }

// A handler can sit in the plugin chain for as long as the chain takes, and
// it writes its reply to the socket when it comes back. Close therefore
// waits for the handlers before it closes the sockets under them.
func TestCloseWaitsForHandlersBeforeClosingSockets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var order []string
		record := func(what string) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, what)
		}

		srv := &Servers{
			listeners:    []listener{&closeRecorder{onClose: func() { record("socket closed") }}},
			gate:         newGate(4),
			drainTimeout: time.Minute,
		}

		hold := make(chan struct{})
		require.True(t, srv.gate.run(func() {
			<-hold
			record("handler done")
		}))

		closed := make(chan struct{})
		go func() {
			srv.Close()
			close(closed)
		}()

		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned while a handler was still running")
		default:
		}

		close(hold)
		<-closed

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"handler done", "socket closed"}, order)
	})
}

// A plugin that never returns delays shutdown by the drain timeout instead
// of holding the process open. The sockets close under it and the log says
// so.
func TestCloseGivesUpAtTheDrainTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := captureLog(t)
		closes := 0
		srv := &Servers{
			listeners:    []listener{&closeRecorder{onClose: func() { closes++ }}},
			gate:         newGate(4),
			drainTimeout: 2 * time.Second,
		}

		hold := make(chan struct{})
		done := make(chan struct{})
		require.True(t, srv.gate.run(func() {
			<-hold
			close(done)
		}))

		start := time.Now()
		srv.Close()
		assert.Equal(t, 2*time.Second, time.Since(start))
		assert.Equal(t, 1, closes)
		assert.Contains(t, buf.String(), "handlers still running after 2s")

		close(hold)
		<-done
	})
}

// Close is reached from a signal handler and from Wait. The second call
// must not sit out the drain timeout again.
func TestCloseDrainsOnlyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		captureLog(t)
		closes := 0
		srv := &Servers{
			listeners:    []listener{&closeRecorder{onClose: func() { closes++ }}},
			gate:         newGate(4),
			drainTimeout: time.Second,
		}

		hold := make(chan struct{})
		done := make(chan struct{})
		require.True(t, srv.gate.run(func() {
			<-hold
			close(done)
		}))

		srv.Close()
		start := time.Now()
		srv.Close()
		assert.Zero(t, time.Since(start), "the second Close must not wait again")
		assert.Equal(t, 2, closes, "every listener is still closed on every call")

		close(hold)
		<-done
	})
}

// A Servers a caller built rather than started has no gate: Close must not
// panic on it and Drops has nothing to report.
func TestZeroValueServersShutsDownQuietly(t *testing.T) {
	s := &Servers{}
	assert.NotPanics(t, s.Close)
	assert.Equal(t, Drops{}, s.Drops())
}

// --- options ---

func TestWithMaxInFlight(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want int
	}{
		{name: "a usable limit is taken", n: 3, want: 3},
		{name: "zero keeps the default", n: 0, want: 64},
		{name: "negative keeps the default", n: -1, want: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Servers{maxInFlight: 64}
			WithMaxInFlight(tc.n)(s)
			assert.Equal(t, tc.want, s.maxInFlight)
		})
	}
}

func TestWithDrainTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    time.Duration
		want time.Duration
	}{
		{name: "a usable timeout is taken", d: time.Minute, want: time.Minute},
		{name: "zero keeps the default", d: 0, want: time.Second},
		{name: "negative keeps the default", d: -time.Hour, want: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Servers{drainTimeout: time.Second}
			WithDrainTimeout(tc.d)(s)
			assert.Equal(t, tc.want, s.drainTimeout)
		})
	}
}

// Start hands every listener the same gate: the limit is about the machine,
// not about one socket, and Close has one set of handlers to wait for.
func TestStartSharesOneGateAcrossListeners(t *testing.T) {
	cfg := testConfig(t,
		[]net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
		[]net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)
	srv, err := Start(cfg, WithMaxInFlight(5), WithDrainTimeout(time.Minute))
	require.NoError(t, err)
	defer srv.Close()

	require.Len(t, srv.listeners, 2)
	require.NotNil(t, srv.gate)
	assert.Equal(t, 5, cap(srv.gate.sem))
	assert.Same(t, srv.gate, asListener6(t, srv.listeners[0]).gate)
	assert.Same(t, srv.gate, asListener4(t, srv.listeners[1]).gate)
	assert.Equal(t, Drops{}, srv.Drops())
}

// --- relay allow list at startup ---

// Without the relay plugin, each family says once at startup that it will
// refuse relayed requests, however many sockets it binds, and the listeners
// carry that decision.
func TestStartWarnsOncePerFamilyWithoutRelayPlugin(t *testing.T) {
	buf := captureLog(t)
	cfg := testConfig(t,
		[]net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}, {IP: net.ParseIP("::1"), Port: 0}},
		[]net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}, {IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)
	srv, err := Start(cfg)
	require.NoError(t, err)
	defer srv.Close()

	assert.Equal(t, 1, buf.count("DHCPv6: no `relay` plugin configured"))
	assert.Equal(t, 1, buf.count("DHCPv4: no `relay` plugin configured"))

	require.Len(t, srv.listeners, 4)
	assert.False(t, asListener6(t, srv.listeners[0]).relayChecked)
	assert.False(t, asListener4(t, srv.listeners[2]).relayChecked)
}

// With the plugin in the chain there is nothing to warn about: the plugin
// decides which relays are answered, and the server stays out of it.
func TestStartWithRelayPluginLeavesRelayedRequestsToIt(t *testing.T) {
	registerTestPlugin(t, &plugins.Plugin{
		Name: relayPluginName,
		Setup6: func(...string) (handler.Handler6, error) {
			return func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }, nil
		},
		Setup4: func(...string) (handler.Handler4, error) {
			return func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }, nil
		},
	})

	buf := captureLog(t)
	cfg := &config.Config{
		Server6: &config.ServerConfig{
			Addresses: []net.UDPAddr{{IP: net.ParseIP("::1"), Port: 0}},
			Plugins:   []config.PluginConfig{{Name: relayPluginName, Args: []string{"allow", "fe80::/10"}}},
		},
		Server4: &config.ServerConfig{
			Addresses: []net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
			Plugins:   []config.PluginConfig{{Name: relayPluginName, Args: []string{"allow", "10.0.1.1"}}},
		},
	}
	srv, err := Start(cfg)
	require.NoError(t, err)
	defer srv.Close()

	assert.NotContains(t, buf.String(), "no `relay` plugin configured")
	require.Len(t, srv.listeners, 2)
	assert.True(t, asListener6(t, srv.listeners[0]).relayChecked)
	assert.True(t, asListener4(t, srv.listeners[1]).relayChecked)
}

// hasRelay4 and hasRelay6 look for the plugin by name anywhere in the
// chain, not just at its head.
func TestHasRelayPlugin(t *testing.T) {
	assert.False(t, hasRelay4(nil))
	assert.False(t, hasRelay4([]plugins.Link4{{Name: "server_id"}, {Name: "range"}}))
	assert.True(t, hasRelay4([]plugins.Link4{{Name: "ratelimit"}, {Name: relayPluginName}}))

	assert.False(t, hasRelay6(nil))
	assert.False(t, hasRelay6([]plugins.Link6{{Name: "server_id"}}))
	assert.True(t, hasRelay6([]plugins.Link6{{Name: relayPluginName}, {Name: "dns"}}))
}
