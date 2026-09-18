// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server_test

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/server"
)

func loopbackUDPAddr4(t *testing.T) net.UDPAddr {
	t.Helper()
	return net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func loopbackUDPAddr6(t *testing.T) net.UDPAddr {
	t.Helper()
	return net.UDPAddr{IP: net.ParseIP("::1"), Port: 0}
}

func TestStartV4Only(t *testing.T) {
	cfg := &config.Config{
		Server4: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr4(t)}},
	}
	srv, err := server.Start(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)
	srv.Close()
	assert.NoError(t, srv.Wait())
}

func TestStartV6Only(t *testing.T) {
	cfg := &config.Config{
		Server6: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr6(t)}},
	}
	srv, err := server.Start(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)
	srv.Close()
	assert.NoError(t, srv.Wait())
}

func TestStartBothV4AndV6(t *testing.T) {
	cfg := &config.Config{
		Server6: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr6(t)}},
		Server4: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr4(t)}},
	}
	srv, err := server.Start(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)
	srv.Close()
	assert.NoError(t, srv.Wait())
}

// TestWaitReturnsAfterClose checks that Wait unblocks once every listener's
// Serve loop has observed net.ErrClosed and returned, without any sleeps.
func TestWaitReturnsAfterClose(t *testing.T) {
	cfg := &config.Config{
		Server6: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr6(t)}},
		Server4: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr4(t)}},
	}
	srv, err := server.Start(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)

	done := make(chan error, 1)
	go func() { done <- srv.Wait() }()

	srv.Close()
	require.NoError(t, <-done)
}

// TestStartLoadPluginsFailure exercises the plugins.LoadPlugins error path:
// a plugin name that was never registered.
func TestStartLoadPluginsFailure(t *testing.T) {
	cfg := &config.Config{
		Server4: &config.ServerConfig{
			Addresses: []net.UDPAddr{loopbackUDPAddr4(t)},
			Plugins:   []config.PluginConfig{{Name: "this-plugin-does-not-exist"}},
		},
	}
	srv, err := server.Start(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)
}

// addressObserver keeps the addresses the server reports binding to, which
// is how a caller outside the package learns the port a listener on port 0
// ended up with.
type addressObserver struct {
	mu        sync.Mutex
	addresses []string
}

func (o *addressObserver) Listener(l events.Listener) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.addresses = append(o.addresses, l.Address)
}

func (o *addressObserver) Plugin(events.Plugin)   {}
func (o *addressObserver) Request(events.Request) {}

func (o *addressObserver) only(t *testing.T) string {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	require.Len(t, o.addresses, 1)
	return o.addresses[0]
}

// The in-flight limit and the drain timeout are constructor options, and a
// server started with them shuts down the way one started without them
// does.
func TestStartWithLimitsAndDrops(t *testing.T) {
	cfg := &config.Config{
		Server4: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr4(t)}},
	}
	srv, err := server.Start(cfg, server.WithMaxInFlight(4), server.WithDrainTimeout(2*time.Second))
	require.NoError(t, err)
	require.NotNil(t, srv)

	assert.Equal(t, server.Drops{}, srv.Drops())
	srv.Close()
	assert.NoError(t, srv.Wait())
}

// A DHCPv4 reply goes to giaddr, and the sender writes giaddr. This sends a
// DISCOVER naming the test's own socket as the relay: with no relay plugin
// configured the server must not answer it, which is the whole point of the
// default. Without the check the reply lands in the socket below.
func TestRelayedRequestIsDroppedWithoutRelayPlugin(t *testing.T) {
	obs := &addressObserver{}
	cfg := &config.Config{
		Server4: &config.ServerConfig{Addresses: []net.UDPAddr{loopbackUDPAddr4(t)}},
	}
	srv, err := server.Start(cfg, server.WithObserver(obs))
	require.NoError(t, err)
	defer srv.Close()

	serverAddr, err := net.ResolveUDPAddr("udp4", obs.only(t))
	require.NoError(t, err)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	localAddr, ok := client.LocalAddr().(*net.UDPAddr)
	require.True(t, ok, "client socket must have a *net.UDPAddr local address")
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithGatewayIP(localAddr.IP),
	)
	require.NoError(t, err)
	_, err = client.WriteToUDP(req.ToBytes(), serverAddr)
	require.NoError(t, err)

	require.Eventually(t, func() bool { return srv.Drops().Relayed == 1 }, 5*time.Second, 5*time.Millisecond,
		"the relayed request should have been dropped and counted")

	require.NoError(t, client.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	n, _, err := client.ReadFromUDP(make([]byte, 1024))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "the server answered a relay it was never told about")
}
