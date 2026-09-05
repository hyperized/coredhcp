// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"net"
	"runtime"
	"testing"

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

// testConfig builds a *config.Config from v6/v4 addresses; a nil slice
// omits that protocol's ServerConfig, a non-nil empty slice includes it with no plugins.
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

// fakeConn4 serves queued reads and records writes. ReadFrom isn't
// concurrency-safe, but WriteTo is, so a handler goroutine can write while the test reads writeCh.
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

func withNewUDP4(t *testing.T, fn func(string, *net.UDPAddr) (net.PacketConn, error)) {
	t.Helper()
	orig := newUDP4
	newUDP4 = fn
	t.Cleanup(func() { newUDP4 = orig })
}

func withNewUDP6(t *testing.T, fn func(string, *net.UDPAddr) (net.PacketConn, error)) {
	t.Helper()
	orig := newUDP6
	newUDP6 = fn
	t.Cleanup(func() { newUDP6 = orig })
}

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

// countingConn counts closes to distinguish leak vs. close vs. double close.
// Embeds *net.UDPConn because NewPacketConn asserts net.Conn, and needs no
// lock because listen4/6 are synchronous.
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

// The wrappers keep a failed bind from returning a typed-nil net.PacketConn,
// which nil checks would wave through; a bad zone fails identically on every platform.
func TestNewUDPConnWrappersReturnANilInterfaceOnFailure(t *testing.T) {
	const zone = "nonexistent-zzz-iface"

	t.Run("v4", func(t *testing.T) {
		c, err := newIPv4UDPConn(zone, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: zone})
		require.Error(t, err)
		assert.True(t, c == nil, "want a nil interface, got %#v", c)
	})

	t.Run("v6", func(t *testing.T) {
		c, err := newIPv6UDPConn(zone, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0, Zone: zone})
		require.Error(t, err)
		assert.True(t, c == nil, "want a nil interface, got %#v", c)
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

// Every listen4 error path after the bind must close the socket exactly
// once; the success path must leave it open since the returned listener closes it later.
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

// A config naming no address at all, which `listen: []` produces, is
// refused rather than quietly starting a server with no sockets.
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

// Wait must handle a Servers with no listeners without blocking or
// panicking, since it's exported and callers can construct one directly.
func TestWaitWithoutListeners(t *testing.T) {
	s := &Servers{}
	assert.NoError(t, s.Wait())
}

// TestStartCleanupJoinsServeGoroutines fails the DHCPv4 bind after a real
// DHCPv6 socket is open; Start must join the v6 read loop before returning or it leaks a goroutine.
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

// TestStartCleanupOnV4ListenFailureClosesV6 opens a real DHCPv6 listener
// first, so the cleanup path exercised here closes a non-empty listeners slice.
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

// registerTestPlugin registers a plugin for the lifetime of the test and
// removes it again, so the shared registry is left as it was found.
func registerTestPlugin(t *testing.T, plugin *plugins.Plugin) {
	t.Helper()
	require.NoError(t, plugins.RegisterPlugin(plugin))
	t.Cleanup(func() { delete(plugins.RegisteredPlugins, plugin.Name) })
}

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
	assert.Same(t, obs, srv.listeners[0].(*listener6).observer)
	assert.Same(t, obs, srv.listeners[1].(*listener4).observer)
	srv.Close()
	require.NoError(t, srv.Wait())

	plain, err := Start(cfg)
	require.NoError(t, err)
	require.Len(t, plain.listeners, 2)
	assert.Nil(t, plain.listeners[0].(*listener6).observer)
	assert.Nil(t, plain.listeners[1].(*listener4).observer)
	plain.Close()
	require.NoError(t, plain.Wait())
}

func TestReportWithoutObserver(t *testing.T) {
	s := &Servers{}
	s.reportPlugins(&plugins.Chains{
		V4: []plugins.Link4{{Name: "four"}},
		V6: []plugins.Link6{{Name: "six"}},
	})
	s.reportListener(events.FamilyV4, &net.UDPAddr{IP: net.IPv4zero, Port: 67}, "eth0")
	assert.Nil(t, s.observer)
}

// Plugin args reach the observer already redacted, since the terminal UI
// displays them, and a plugin's argument list is where a password or token
// lands. See config.RedactArgs.
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
