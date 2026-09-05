// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package handler defines the handler function types every plugin implements
// for DHCPv4 and DHCPv6 request processing.
package handler

import (
	"context"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// Handler6 is a function that is called on a given DHCPv6 packet.
// It returns a DHCPv6 packet and a boolean.
// If the boolean is true, this will be the last handler to be called.
// The two input packets are the original request, and a response packet.
// The response packet may or may not be modified by the function, and
// the result will be returned by the handler.
// If the returned boolean is true, the returned packet may be nil or
// invalid, in which case no response will be sent.
type Handler6 func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool)

// Handler4 behaves like Handler6, but for DHCPv4 packets.
type Handler4 func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)

// Handler6Ctx is Handler6 with a context in front of the packets, for a
// plugin that needs to know where the request came from as well as what it
// says.
//
// The stop and drop rules are Handler6's: a true return ends the chain, and a
// nil response means no answer is sent. ctx is never nil, and carries a
// RequestInfo whenever the server built one, which it does for any chain
// holding at least one context-aware plugin. Read it with RequestInfoFrom and
// handle the false case, since a handler can also be called through the
// legacy plugins.LoadPlugins API, which has no request to describe.
//
// The context belongs to the call: a handler must not keep it, or anything
// derived from it, after it returns.
type Handler6Ctx func(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool)

// Handler4Ctx behaves like Handler6Ctx, but for DHCPv4 packets.
type Handler4Ctx func(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
