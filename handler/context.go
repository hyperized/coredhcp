// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package handler

import (
	"context"
	"net/netip"
)

// RequestInfo is what the server knows about a request beyond the packet.
// It is passed by value, so a handler reads it without synchronisation.
type RequestInfo struct {
	// Empty when the socket did not report an arrival interface; IfIndex
	// is then 0 too. Prefer IfIndex when storing: it survives a rename.
	Interface string

	IfIndex int

	// Peer has any IPv6 zone stripped, so a link-local address compares
	// equal to the same address written in a configuration file.
	Peer netip.AddrPort

	// Local is the listening socket's address, which for a wildcard bind is
	// the wildcard rather than the address the client sent to.
	Local netip.AddrPort
}

type requestInfoKey struct{}

// WithRequestInfo returns a copy of ctx carrying info.
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom returns the RequestInfo attached to ctx, if any.
// The false case is reachable: plugins.LoadPlugins attaches none.
func RequestInfoFrom(ctx context.Context) (RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info, ok
}
