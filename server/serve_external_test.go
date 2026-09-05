// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
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

// TestWaitReturnsAfterClose checks Wait unblocks once every listener's
// Serve loop has observed net.ErrClosed and returned.
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
