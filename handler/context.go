// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package handler

import (
	"context"
	"net/netip"
)

// RequestInfo is what the server knows about a request beyond the packet
// itself: the interface the datagram arrived on and the addresses of the
// exchange. A plugin needs those to pick a subnet per interface, to rate
// limit a source, or to check a relay against a trust list, and none of it
// can be recovered from the DHCP payload.
//
// It travels through the handler chain in a context.Context and comes back
// out of RequestInfoFrom as a copy, so a handler reads it without
// synchronisation and cannot write into what the server holds.
type RequestInfo struct {
	// Interface is the name of the interface the datagram came in on. It is
	// empty when the listener is not bound to an interface and the socket
	// did not say which one the packet arrived on.
	Interface string

	// IfIndex is the index of that same interface, and is 0 in exactly the
	// cases where Interface is empty. An index survives a rename where the
	// cached name does not, so prefer it when the value is stored.
	IfIndex int

	// Peer is the UDP source of the datagram: the client itself, or the
	// relay agent that forwarded it. Any IPv6 zone is stripped, so a
	// link-local peer compares equal to the same address in a configuration
	// file and keys a map the same way from every interface. Interface says
	// which interface it was seen on.
	Peer netip.AddrPort

	// Local is the address of the listening socket the datagram arrived on,
	// which for a server bound to the wildcard address is the wildcard, not
	// the address the client sent to.
	Local netip.AddrPort
}

// requestInfoKey is the key RequestInfo is stored under. Its type is
// unexported and has no fields, so no other package can construct the key,
// read the value, or shadow it. This is how net/http hands a connection's
// local address to a request handler.
type requestInfoKey struct{}

// WithRequestInfo returns a copy of ctx carrying info, for the server to hand
// to a Handler4Ctx or Handler6Ctx. Plugins read it back with RequestInfoFrom;
// they have no reason to call this, beyond testing a handler of their own.
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom returns the RequestInfo the server attached to ctx.
//
// The boolean is false when the context carries none, and a handler has to
// cope with that rather than treat it as impossible: it is what a
// context-aware plugin sees when it is called through the legacy
// plugins.LoadPlugins API, or straight from a test. The returned zero value
// is safe to read either way.
func RequestInfoFrom(ctx context.Context) (RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info, ok
}
