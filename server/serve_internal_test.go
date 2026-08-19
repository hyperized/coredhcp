// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/config"
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
func withNewUDP4(t *testing.T, fn func(string, *net.UDPAddr) (*net.UDPConn, error)) {
	t.Helper()
	orig := newUDP4
	newUDP4 = fn
	t.Cleanup(func() { newUDP4 = orig })
}

// withNewUDP6 swaps the newUDP6 package var for the duration of the test.
func withNewUDP6(t *testing.T, fn func(string, *net.UDPAddr) (*net.UDPConn, error)) {
	t.Helper()
	orig := newUDP6
	newUDP6 = fn
	t.Cleanup(func() { newUDP6 = orig })
}

// closedUDP4Conn returns an already-closed *net.UDPConn suitable as a
// newUDP4/newUDP6 stand-in to drive SetControlMessage/JoinGroup failures.
func closedUDPConn(t *testing.T, network string, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, addr)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	return c
}

func TestListen4HappyPath(t *testing.T) {
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	require.NotNil(t, l4)
	defer func() { _ = l4.Close() }()
	assert.NotNil(t, l4.conn4)
}

func TestListen4ConstructorError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("constructor boom")
	})
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l4)
	assert.Contains(t, err.Error(), "constructor boom")
}

func TestListen4SetControlMessageError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return closedUDPConn(t, "udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}), nil
	})
	// Zone empty so listen4 takes the SetControlMessage branch.
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l4)
}

func TestListen4ZoneLookupError(t *testing.T) {
	withNewUDP4(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	})
	l4, err := listen4(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: "nonexistent-zzz-iface"})
	require.Error(t, err)
	assert.Nil(t, l4)
	assert.Contains(t, err.Error(), "could not find interface")
}

func TestListen4JoinGroupError(t *testing.T) {
	iface := loopbackInterfaceName(t)
	withNewUDP4(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
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

func TestListen6HappyPath(t *testing.T) {
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.NoError(t, err)
	require.NotNil(t, l6)
	defer func() { _ = l6.Close() }()
	assert.NotNil(t, l6.conn6)
}

func TestListen6ConstructorError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("constructor boom")
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l6)
	assert.Contains(t, err.Error(), "constructor boom")
}

func TestListen6SetControlMessageError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return closedUDPConn(t, "udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}), nil
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	require.Error(t, err)
	assert.Nil(t, l6)
}

func TestListen6ZoneLookupError(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	})
	l6, err := listen6(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 0, Zone: "nonexistent-zzz-iface"})
	require.Error(t, err)
	assert.Nil(t, l6)
	assert.Contains(t, err.Error(), "could not find interface")
}

func TestListen6JoinGroupError(t *testing.T) {
	iface := loopbackInterfaceName(t)
	withNewUDP6(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
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

// TestStartCleanupOnV6ListenFailure drives Start's "goto cleanup" path via
// the DHCPv6 listen loop, with no listeners ever successfully opened.
func TestStartCleanupOnV6ListenFailure(t *testing.T) {
	withNewUDP6(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
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
	withNewUDP4(t, func(string, *net.UDPAddr) (*net.UDPConn, error) {
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
