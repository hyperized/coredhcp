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

// Handler6 processes a DHCPv6 request and the response built so far.
// A true return ends the chain; a nil response means nothing is sent.
type Handler6 func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool)

// Handler4 behaves like Handler6, but for DHCPv4 packets.
type Handler4 func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)

// Handler6Ctx is Handler6 with a context carrying RequestInfo in front.
// The context can carry none, so handle RequestInfoFrom's false case.
type Handler6Ctx func(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool)

// Handler4Ctx behaves like Handler6Ctx, but for DHCPv4 packets.
type Handler4Ctx func(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
