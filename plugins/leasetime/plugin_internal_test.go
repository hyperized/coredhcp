// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasetime

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginStateHandler4(t *testing.T) {
	const leaseTime = 42 * time.Second

	cases := []struct {
		name      string
		buildReq  func(t *testing.T) *dhcpv4.DHCPv4
		buildResp func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4
		wantSet   bool
		wantValue time.Duration
		wantStop  bool
	}{
		{
			name: "inform message is left untouched",
			buildReq: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
				require.NoError(t, err)
				req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
				return req
			},
			buildResp: func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
				t.Helper()
				resp, err := dhcpv4.NewReplyFromRequest(req)
				require.NoError(t, err)
				return resp
			},
			wantSet:  false,
			wantStop: false,
		},
		{
			name: "non boot-request opcode is left untouched",
			buildReq: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
				require.NoError(t, err)
				req.OpCode = dhcpv4.OpcodeBootReply
				return req
			},
			buildResp: func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
				t.Helper()
				resp, err := dhcpv4.NewReplyFromRequest(req)
				require.NoError(t, err)
				return resp
			},
			wantSet:  false,
			wantStop: false,
		},
		{
			name: "lease time is set when absent",
			buildReq: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
				require.NoError(t, err)
				return req
			},
			buildResp: func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
				t.Helper()
				resp, err := dhcpv4.NewReplyFromRequest(req)
				require.NoError(t, err)
				return resp
			},
			wantSet:   true,
			wantValue: leaseTime,
			wantStop:  false,
		},
		{
			name: "existing lease time is not overwritten",
			buildReq: func(t *testing.T) *dhcpv4.DHCPv4 {
				t.Helper()
				req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
				require.NoError(t, err)
				return req
			},
			buildResp: func(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
				t.Helper()
				resp, err := dhcpv4.NewReplyFromRequest(req)
				require.NoError(t, err)
				resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(99 * time.Second))
				return resp
			},
			wantSet:   true,
			wantValue: 99 * time.Second,
			wantStop:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pluginState{leaseTime: leaseTime}
			req := tc.buildReq(t)
			resp := tc.buildResp(t, req)

			got, stop := p.Handler4(req, resp)
			require.NotNil(t, got)
			assert.Equal(t, tc.wantStop, stop)

			has := got.Options.Has(dhcpv4.OptionIPAddressLeaseTime)
			assert.Equal(t, tc.wantSet, has)
			if tc.wantSet {
				assert.Equal(t, tc.wantValue, got.IPAddressLeaseTime(0))
			}
		})
	}
}
