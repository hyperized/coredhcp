// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leaseapi serves the leases the server currently holds over a
// read-only HTTP API, on a unix socket or on loopback.
//
// Nothing in coredhcp could answer "who holds what right now"
// (coredhcp/coredhcp#111, the most-asked-for thing in that tracker), which
// also makes a remote terminal UI impossible: every lease lives in a plugin's
// own map behind that plugin's own lock. The lease-holding plugins now
// register themselves with the leases package during setup, and this plugin
// serves what the registry reports.
//
//	server4:
//	  plugins:
//	    - leaseapi: unix:/run/coredhcp/api.sock mode:0660
//	    - leaseapi: tcp:127.0.0.1:9755
//
// # There is no authentication
//
// The socket's permissions are the authentication, which is why the default
// mode is 0600 and why a tcp address has to be a loopback one. An operator who
// wants this reachable from another host puts a reverse proxy in front of it
// and authenticates there, or forwards the socket over ssh. Serving it on a
// routable address would publish every client MAC, DUID, hostname and address
// on the network to anyone who can reach the port.
//
// The API is read-only. There is no endpoint that frees a lease, edits a
// reservation or changes the configuration, and there is no plan for one:
// writes would need an authorisation model this has no way to provide, and a
// forged DHCPRELEASE is already the cheapest way to attack a pool.
//
// # Where it goes in the chain
//
// Anywhere. Both handlers return the response untouched and never end the
// chain; the plugin exists in the chain only because setup is what starts the
// listener. When server4 and server6 both configure the same address they
// share one listener, and the answers cover both families either way, since
// the registry is global.
package leaseapi
