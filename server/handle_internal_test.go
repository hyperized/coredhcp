// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
)

var testMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

// --- buildReply6 ---

func mustSolicit(t *testing.T, rapidCommit bool) *dhcpv6.Message {
	t.Helper()
	var mods []dhcpv6.Modifier
	if rapidCommit {
		mods = append(mods, dhcpv6.WithRapidCommit)
	}
	m, err := dhcpv6.NewSolicit(testMAC, mods...)
	require.NoError(t, err)
	return m
}

// mustMessage6 builds a DHCPv6 message of the given type with a Client ID
// option attached, since NewReplyFromMessage requires one for every type it
// accepts.
func mustMessage6(t *testing.T, mt dhcpv6.MessageType) *dhcpv6.Message {
	t.Helper()
	m, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	m.MessageType = mt
	duid := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: testMAC,
	}
	m.AddOption(dhcpv6.OptClientID(duid))
	return m
}

// datagramBuf mimics the buffer shape Serve() hands to HandleMsg4/HandleMsg6:
// a slice with MaxDatagram capacity, resliced down to the received length.
// Calling HandleMsg4/HandleMsg6 directly with an under-sized buffer would
// have them return an under-capacity buffer to the shared bufpool, which
// later panics when Serve() reslices a pooled buffer back up to
// MaxDatagram.
func datagramBuf(data []byte) []byte {
	b := make([]byte, MaxDatagram)
	n := copy(b, data)
	return b[:n]
}

func TestBuildReply6(t *testing.T) {
	tests := []struct {
		name     string
		in       dhcpv6.DHCPv6
		wantErr  string
		wantType dhcpv6.MessageType
	}{
		{
			name:     "solicit without rapid commit becomes advertise",
			in:       mustSolicit(t, false),
			wantType: dhcpv6.MessageTypeAdvertise,
		},
		{
			name:     "solicit with rapid commit becomes reply",
			in:       mustSolicit(t, true),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "request becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeRequest),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "confirm becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeConfirm),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "renew becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeRenew),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "rebind becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeRebind),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "release becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeRelease),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:     "information-request becomes reply",
			in:       mustMessage6(t, dhcpv6.MessageTypeInformationRequest),
			wantType: dhcpv6.MessageTypeReply,
		},
		{
			name:    "unsupported message type",
			in:      mustMessage6(t, dhcpv6.MessageTypeAdvertise),
			wantErr: "not supported",
		},
		{
			name:    "GetInnerMessage error propagates",
			in:      &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward},
			wantErr: "cannot get inner message",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := buildReply6(tc.in)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tc.wantType, resp.Type())
		})
	}
}

// --- buildReply4 ---

func mustRequest4(t *testing.T, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	req, err := dhcpv4.New(append([]dhcpv4.Modifier{dhcpv4.WithHwAddr(testMAC)}, mods...)...)
	require.NoError(t, err)
	return req
}

func TestBuildReply4(t *testing.T) {
	badOpcodeReq := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	badOpcodeReq.OpCode = dhcpv4.OpcodeBootReply

	tests := []struct {
		name     string
		in       *dhcpv4.DHCPv4
		wantErr  string
		wantType dhcpv4.MessageType
	}{
		{
			name:     "discover becomes offer",
			in:       mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover)),
			wantType: dhcpv4.MessageTypeOffer,
		},
		{
			name:     "request becomes ack",
			in:       mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest)),
			wantType: dhcpv4.MessageTypeAck,
		},
		{
			name:     "inform becomes ack",
			in:       mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeInform)),
			wantType: dhcpv4.MessageTypeAck,
		},
		{
			name:     "release gets no message type set",
			in:       mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease)),
			wantType: dhcpv4.MessageTypeNone,
		},
		{
			// No OptMessageType set at all -> MessageType() == MessageTypeNone,
			// which the switch does not handle.
			name:    "unhandled message type",
			in:      mustRequest4(t),
			wantErr: "unhandled message type",
		},
		{
			name:    "bad opcode",
			in:      badOpcodeReq,
			wantErr: "unsupported opcode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := buildReply4(tc.in)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tc.wantType, resp.MessageType())
		})
	}
}

// --- applyHandlers4 / applyHandlers6 ---

func TestApplyHandlers4(t *testing.T) {
	base := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))

	t.Run("empty chain returns resp unchanged and no stop position", func(t *testing.T) {
		resp, stoppedAt := applyHandlers4(nil, base, base)
		assert.Same(t, base, resp)
		assert.Equal(t, -1, stoppedAt)
	})

	t.Run("chain that runs to the end reports no stop position", func(t *testing.T) {
		pass := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }
		resp, stoppedAt := applyHandlers4(chain4(pass, pass), base, base)
		assert.Same(t, base, resp)
		assert.Equal(t, -1, stoppedAt)
	})

	t.Run("chain runs in order until stop", func(t *testing.T) {
		var order []int
		h1 := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 1)
			return resp, false
		}
		h2 := func(_, _ *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 2)
			return nil, true
		}
		h3 := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			order = append(order, 3)
			return resp, false
		}
		resp, stoppedAt := applyHandlers4(chain4(h1, h2, h3), base, base)
		assert.Nil(t, resp)
		assert.Equal(t, []int{1, 2}, order)
		assert.Equal(t, 1, stoppedAt)
	})
}

func TestApplyHandlers6(t *testing.T) {
	base := mustSolicit(t, false)

	t.Run("empty chain returns resp unchanged and no stop position", func(t *testing.T) {
		resp, stoppedAt := applyHandlers6(nil, base, base)
		assert.Same(t, base, resp)
		assert.Equal(t, -1, stoppedAt)
	})

	t.Run("chain that runs to the end reports no stop position", func(t *testing.T) {
		pass := func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return resp, false }
		resp, stoppedAt := applyHandlers6(chain6(pass, pass), base, base)
		assert.Same(t, base, resp)
		assert.Equal(t, -1, stoppedAt)
	})

	t.Run("chain runs in order until stop", func(t *testing.T) {
		var order []int
		h1 := func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 1)
			return resp, false
		}
		h2 := func(_, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 2)
			return nil, true
		}
		h3 := func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			order = append(order, 3)
			return resp, false
		}
		resp, stoppedAt := applyHandlers6(chain6(h1, h2, h3), base, base)
		assert.Nil(t, resp)
		assert.Equal(t, []int{1, 2}, order)
		assert.Equal(t, 1, stoppedAt)
	})
}

// --- encapsulateRelay6 ---

func TestEncapsulateRelay6(t *testing.T) {
	t.Run("non-relay request passes through unchanged", func(t *testing.T) {
		req := mustMessage6(t, dhcpv6.MessageTypeRequest)
		resp := mustMessage6(t, dhcpv6.MessageTypeReply)
		out, err := encapsulateRelay6(req, resp)
		require.NoError(t, err)
		assert.Same(t, resp, out)
	})

	t.Run("relay request re-encapsulates a Message response", func(t *testing.T) {
		inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
		req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
		require.NoError(t, err)
		resp := mustMessage6(t, dhcpv6.MessageTypeReply)

		out, err := encapsulateRelay6(req, resp)
		require.NoError(t, err)
		require.NotNil(t, out)
		relayOut, ok := out.(*dhcpv6.RelayMessage)
		require.True(t, ok)
		assert.Equal(t, dhcpv6.MessageTypeRelayReply, relayOut.Type())
	})

	t.Run("relay request with a non-Message response passes through", func(t *testing.T) {
		inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
		req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
		require.NoError(t, err)

		// resp is itself a *RelayMessage, i.e. not a *dhcpv6.Message.
		resp, err := dhcpv6.EncapsulateRelay(mustMessage6(t, dhcpv6.MessageTypeReply), dhcpv6.MessageTypeRelayReply, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
		require.NoError(t, err)

		out, err := encapsulateRelay6(req, resp)
		require.NoError(t, err)
		assert.Same(t, resp, out)
	})

	t.Run("relay re-encapsulation error propagates", func(t *testing.T) {
		inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
		// A RelayReply (not RelayForward) outer wrapper makes
		// NewRelayReplFromRelayForw reject it.
		req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayReply, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
		require.NoError(t, err)
		resp := mustMessage6(t, dhcpv6.MessageTypeReply)

		out, err := encapsulateRelay6(req, resp)
		require.Error(t, err)
		assert.Nil(t, out)
	})
}

// --- replyDestination4 ---

func TestReplyDestination4(t *testing.T) {
	ack := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	nak := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeNak))

	tests := []struct {
		name            string
		req             *dhcpv4.DHCPv4
		resp            *dhcpv4.DHCPv4
		src             *net.UDPAddr
		wantIP          net.IP
		wantPort        int
		wantUseEthernet bool
	}{
		{
			name:     "gateway set takes priority",
			req:      mustRequest4(t, dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1"))),
			resp:     ack,
			wantIP:   net.ParseIP("10.0.0.1"),
			wantPort: dhcpv4.ServerPort,
		},
		{
			// RFC 8357: the relay may send from any port, and the reply
			// must go back to that port.
			name:     "relayed request replies to observed source port",
			req:      mustRequest4(t, dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1"))),
			resp:     ack,
			src:      &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 6767},
			wantIP:   net.ParseIP("10.0.0.1"),
			wantPort: 6767,
		},
		{
			name:     "relayed request with zero source port keeps the server port",
			req:      mustRequest4(t, dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1"))),
			resp:     ack,
			src:      &net.UDPAddr{IP: net.ParseIP("10.0.0.1")},
			wantIP:   net.ParseIP("10.0.0.1"),
			wantPort: dhcpv4.ServerPort,
		},
		{
			name:     "nak is broadcast",
			req:      mustRequest4(t),
			resp:     nak,
			wantIP:   net.IPv4bcast,
			wantPort: dhcpv4.ClientPort,
		},
		{
			name:     "client IP set is unicast",
			req:      mustRequest4(t, dhcpv4.WithClientIP(net.ParseIP("192.0.2.5"))),
			resp:     ack,
			wantIP:   net.ParseIP("192.0.2.5"),
			wantPort: dhcpv4.ClientPort,
		},
		{
			name: "broadcast flag set",
			req: func() *dhcpv4.DHCPv4 {
				r := mustRequest4(t)
				r.SetBroadcast()
				return r
			}(),
			resp:     ack,
			wantIP:   net.IPv4bcast,
			wantPort: dhcpv4.ClientPort,
		},
		{
			name:            "default is layer-2 unicast to YourIPAddr",
			req:             mustRequest4(t),
			resp:            mustRequest4(t, dhcpv4.WithYourIP(net.ParseIP("192.0.2.9"))),
			wantIP:          net.ParseIP("192.0.2.9"),
			wantPort:        dhcpv4.ClientPort,
			wantUseEthernet: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer, useEthernet := replyDestination4(tc.req, tc.resp, tc.src)
			require.NotNil(t, peer)
			assert.True(t, tc.wantIP.Equal(peer.IP), "IP: got %v want %v", peer.IP, tc.wantIP)
			assert.Equal(t, tc.wantPort, peer.Port)
			assert.Equal(t, tc.wantUseEthernet, useEthernet)
		})
	}
}

// --- replyIfIndex / oobIfIndex4 / oobIfIndex6 ---

func TestReplyIfIndex(t *testing.T) {
	assert.Equal(t, 5, replyIfIndex(5, 9))
	assert.Equal(t, 9, replyIfIndex(0, 9))
	assert.Equal(t, 0, replyIfIndex(0, 0))
}

func TestOobIfIndex4(t *testing.T) {
	assert.Equal(t, 0, oobIfIndex4(nil))
	assert.Equal(t, 3, oobIfIndex4(&ipv4.ControlMessage{IfIndex: 3}))
}

func TestOobIfIndex6(t *testing.T) {
	assert.Equal(t, 0, oobIfIndex6(nil))
	assert.Equal(t, 4, oobIfIndex6(&ipv6.ControlMessage{IfIndex: 4}))
}

// --- HandleMsg4 ---

func newTestListener4(handlers []handler.Handler4, conn *fakeConn4) *listener4 {
	return &listener4{conn4: conn, chain: chain4(handlers...)}
}

// chain4 turns bare handlers into a chain, naming each link after its
// position so a test can tell from an event which one stopped the chain.
func chain4(handlers ...handler.Handler4) []plugins.Link4 {
	chain := make([]plugins.Link4, 0, len(handlers))
	for i, h := range handlers {
		chain = append(chain, plugins.Link4{Name: fmt.Sprintf("plugin%d", i+1), Handler: h})
	}
	return chain
}

// chain6 is chain4 for the DHCPv6 chain.
func chain6(handlers ...handler.Handler6) []plugins.Link6 {
	chain := make([]plugins.Link6, 0, len(handlers))
	for i, h := range handlers {
		chain = append(chain, plugins.Link6{Name: fmt.Sprintf("plugin%d", i+1), Handler: h})
	}
	return chain
}

func TestHandleMsg4ParseError(t *testing.T) {
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.HandleMsg4(datagramBuf([]byte{0xff}), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg4BuildReplyError(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.OpCode = dhcpv4.OpcodeBootReply
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg4HandlerDropsRequest(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	drop := func(_, _ *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return nil, true }
	conn := &fakeConn4{}
	l := newTestListener4([]handler.Handler4{drop}, conn)
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg4WriteToError(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast() // avoid the ethernet path so WriteTo is reached
	conn := &fakeConn4{writeErr: errors.New("write boom")}
	l := newTestListener4(nil, conn)
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	require.Len(t, conn.writes, 1)
}

func TestHandleMsg4BroadcastWriteSuccess(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast()
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.Index = 5 // bound interface, so the broadcast reply carries a control message
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	require.Len(t, conn.writes, 1)
	assert.True(t, net.IPv4bcast.Equal(conn.writes[0].dst.(*net.UDPAddr).IP))
	require.NotNil(t, conn.writes[0].cm)
	assert.Equal(t, 5, conn.writes[0].cm.IfIndex)
}

func TestHandleMsg4LinkLocalUnicastNoEthernet(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover), dhcpv4.WithClientIP(net.ParseIP("169.254.1.2")))
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.Index = 5
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	require.Len(t, conn.writes, 1)
	assert.True(t, net.ParseIP("169.254.1.2").Equal(conn.writes[0].dst.(*net.UDPAddr).IP))
	require.NotNil(t, conn.writes[0].cm)
	assert.Equal(t, 5, conn.writes[0].cm.IfIndex)
}

func TestHandleMsg4PlainUnicastNoControlMessage(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover), dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")))
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	require.Len(t, conn.writes, 1)
	assert.Nil(t, conn.writes[0].cm)
}

func TestHandleMsg4EthernetWithoutInterfaceInfoDoesNotCrash(t *testing.T) {
	// useEthernet path with no bound interface (l.Index == 0) and no oob
	// interface info: woob stays nil. This used to crash the server by
	// dereferencing woob; now it must just log and return.
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover)) // default case -> useEthernet
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)

	called := false
	origSendEthernet := sendEthernetFn
	sendEthernetFn = func(_ net.Interface, _ *dhcpv4.DHCPv4) error {
		called = true
		return nil
	}
	defer func() { sendEthernetFn = origSendEthernet }()

	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	assert.False(t, called)
	assert.Empty(t, conn.writes)
}

func TestHandleMsg4EthernetInterfaceByIndexError(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover)) // default case -> useEthernet
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.Index = 999999 // absurd index: net.InterfaceByIndex must fail

	called := false
	origSendEthernet := sendEthernetFn
	sendEthernetFn = func(_ net.Interface, _ *dhcpv4.DHCPv4) error {
		called = true
		return nil
	}
	defer func() { sendEthernetFn = origSendEthernet }()

	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	assert.False(t, called)
	assert.Empty(t, conn.writes)
}

func TestHandleMsg4EthernetSendSuccessAndFailure(t *testing.T) {
	loName := loopbackInterfaceName(t)
	lo, err := net.InterfaceByName(loName)
	require.NoError(t, err)

	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	conn := &fakeConn4{}
	l := newTestListener4(nil, conn)
	l.Index = lo.Index

	origSendEthernet := sendEthernetFn
	defer func() { sendEthernetFn = origSendEthernet }()

	t.Run("success", func(t *testing.T) {
		var gotIface net.Interface
		var gotResp *dhcpv4.DHCPv4
		sendEthernetFn = func(iface net.Interface, resp *dhcpv4.DHCPv4) error {
			gotIface = iface
			gotResp = resp
			return nil
		}
		l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
		assert.Equal(t, lo.Index, gotIface.Index)
		require.NotNil(t, gotResp)
		assert.Equal(t, dhcpv4.MessageTypeOffer, gotResp.MessageType())
		assert.Empty(t, conn.writes)
	})

	t.Run("failure is logged and swallowed", func(t *testing.T) {
		sendEthernetFn = func(_ net.Interface, _ *dhcpv4.DHCPv4) error {
			return errors.New("send boom")
		}
		assert.NotPanics(t, func() {
			l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
		})
		assert.Empty(t, conn.writes)
	})
}

// --- HandleMsg6 ---

func newTestListener6(handlers []handler.Handler6, conn *fakeConn6) *listener6 {
	return &listener6{conn6: conn, chain: chain6(handlers...)}
}

func TestHandleMsg6ParseError(t *testing.T) {
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf([]byte{0x01}), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg6BuildReplyError(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeAdvertise) // server never accepts this as a request
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg6HandlerDropsRequest(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	drop := func(_, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return nil, true }
	conn := &fakeConn6{}
	l := newTestListener6([]handler.Handler6{drop}, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg6EncapsulateRelayError(t *testing.T) {
	inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
	// Outer wrapper is RelayReply, not RelayForward: encapsulateRelay6 will
	// fail to build a reply once a handler produces a *Message response.
	req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayReply, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{})
	assert.Empty(t, conn.writes)
}

func TestHandleMsg6WriteToError(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	conn := &fakeConn6{writeErr: errors.New("write boom")}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
	require.Len(t, conn.writes, 1)
}

func TestHandleMsg6GlobalPeerNoControlMessage(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
	require.Len(t, conn.writes, 1)
	assert.Nil(t, conn.writes[0].cm)
}

func TestHandleMsg6LinkLocalPeerUsesBoundInterface(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.Index = 7
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("fe80::1")})
	require.Len(t, conn.writes, 1)
	require.NotNil(t, conn.writes[0].cm)
	assert.Equal(t, 7, conn.writes[0].cm.IfIndex)
}

func TestHandleMsg6LinkLocalPeerUsesOobInterface(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), &ipv6.ControlMessage{IfIndex: 9}, &net.UDPAddr{IP: net.ParseIP("fe80::1")})
	require.Len(t, conn.writes, 1)
	require.NotNil(t, conn.writes[0].cm)
	assert.Equal(t, 9, conn.writes[0].cm.IfIndex)
}

func TestHandleMsg6LinkLocalPeerWithoutInterfaceInfo(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("fe80::1")})
	require.Len(t, conn.writes, 1)
	assert.Nil(t, conn.writes[0].cm)
}

func TestHandleMsg6RelaySuccess(t *testing.T) {
	inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
	req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)
	conn := &fakeConn6{}
	l := newTestListener6(nil, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
	require.Len(t, conn.writes, 1)

	sent, err := dhcpv6.FromBytes(conn.writes[0].b)
	require.NoError(t, err)
	assert.Equal(t, dhcpv6.MessageTypeRelayReply, sent.Type())
}

func TestHandleMsg6RelayNonMessagePassthrough(t *testing.T) {
	inner := mustMessage6(t, dhcpv6.MessageTypeRequest)
	req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)

	relayResp, err := dhcpv6.EncapsulateRelay(mustMessage6(t, dhcpv6.MessageTypeReply), dhcpv6.MessageTypeRelayReply, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)
	passthrough := func(_, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return relayResp, true }

	conn := &fakeConn6{}
	l := newTestListener6([]handler.Handler6{passthrough}, conn)
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
	require.Len(t, conn.writes, 1)
	assert.Equal(t, relayResp.ToBytes(), conn.writes[0].b)
}

// --- Serve loops ---

func TestListener4ServeReturnsNilOnClosed(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast()
	writeCh := make(chan struct{}, 1)
	conn := &fakeConn4{
		writeCh: writeCh,
		reads: []fakeReadResult4{
			{data: req.ToBytes(), peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}},
			{err: net.ErrClosed},
		},
	}
	l := newTestListener4(nil, conn)
	err := l.Serve()
	require.NoError(t, err)
	<-writeCh // wait for the HandleMsg4 goroutine spawned for the first packet
	assert.Len(t, conn.writes, 1)
}

func TestListener4ServeReturnsError(t *testing.T) {
	conn := &fakeConn4{
		reads: []fakeReadResult4{{err: errors.New("read boom")}},
	}
	l := newTestListener4(nil, conn)
	err := l.Serve()
	require.Error(t, err)
	assert.Equal(t, "read boom", err.Error())
}

func TestListener6ServeReturnsNilOnClosed(t *testing.T) {
	req := mustMessage6(t, dhcpv6.MessageTypeRequest)
	writeCh := make(chan struct{}, 1)
	conn := &fakeConn6{
		writeCh: writeCh,
		reads: []fakeReadResult6{
			{data: req.ToBytes(), peer: &net.UDPAddr{IP: net.ParseIP("2001:db8::1")}},
			{err: net.ErrClosed},
		},
	}
	l := newTestListener6(nil, conn)
	err := l.Serve()
	require.NoError(t, err)
	<-writeCh
	assert.Len(t, conn.writes, 1)
}

func TestListener6ServeReturnsError(t *testing.T) {
	conn := &fakeConn6{
		reads: []fakeReadResult6{{err: errors.New("read boom")}},
	}
	l := newTestListener6(nil, conn)
	err := l.Serve()
	require.Error(t, err)
	assert.Equal(t, "read boom", err.Error())
}

// TestBufpoolNewAllocatesMaxDatagram covers bufpool's New initializer
// directly. Whether sync.Pool.Get ever actually calls New is unspecified
// (it depends on whether the pool already holds an item), so the only
// deterministic way to exercise the closure's statements is to call it
// itself rather than trying to force the pool empty.
func TestBufpoolNewAllocatesMaxDatagram(t *testing.T) {
	got := bufpool.New()
	b, ok := got.(*[]byte)
	require.True(t, ok)
	assert.Len(t, *b, MaxDatagram)
}

// --- observer reporting ---

// recordObserver collects everything the server reports. Request runs on the
// goroutine handling each packet, so the slices are guarded.
type recordObserver struct {
	mu        sync.Mutex
	requests  []events.Request
	listeners []events.Listener
	plugins   []events.Plugin
}

func (o *recordObserver) Request(r events.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, r)
}

func (o *recordObserver) Listener(l events.Listener) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.listeners = append(o.listeners, l)
}

func (o *recordObserver) Plugin(p events.Plugin) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.plugins = append(o.plugins, p)
}

// only returns the one request the observer saw. Every datagram must produce
// exactly one event, whatever became of it, so anything else is a failure.
func (o *recordObserver) only(t *testing.T) events.Request {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	require.Len(t, o.requests, 1)
	return o.requests[0]
}

// fixedDUID has no timestamp in it, unlike the DUID-LLT mustMessage6 builds,
// so the hex an event carries is the same on every run.
var fixedDUID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: testMAC}

// fixedDUIDHex is fixedDUID as the server renders it: DUID type 3, hardware
// type 1, then the MAC.
const fixedDUIDHex = "00030001001122334455"

// message6 builds a DHCPv6 message of the given type carrying fixedDUID as
// its client ID, plus any options the test needs.
func message6(t *testing.T, mt dhcpv6.MessageType, opts ...dhcpv6.Option) *dhcpv6.Message {
	t.Helper()
	m, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	m.MessageType = mt
	m.AddOption(dhcpv6.OptClientID(fixedDUID))
	for _, o := range opts {
		m.AddOption(o)
	}
	return m
}

// observedListener4 is newTestListener4 with an observer attached.
func observedListener4(handlers []handler.Handler4, conn *fakeConn4) (*listener4, *recordObserver) {
	obs := &recordObserver{}
	l := newTestListener4(handlers, conn)
	l.observer = obs
	return l, obs
}

// observedListener6 is newTestListener6 with an observer attached.
func observedListener6(handlers []handler.Handler6, conn *fakeConn6) (*listener6, *recordObserver) {
	obs := &recordObserver{}
	l := newTestListener6(handlers, conn)
	l.observer = obs
	return l, obs
}

func TestHandleMsg4ObserverParseError(t *testing.T) {
	l, obs := observedListener4(nil, &fakeConn4{})
	l.Index, l.Name = 5, "eth0"
	l.HandleMsg4(datagramBuf([]byte{0xff}), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 68})

	ev := obs.only(t)
	assert.False(t, ev.Time.IsZero())
	assert.Equal(t, events.FamilyV4, ev.Family)
	assert.Equal(t, "eth0", ev.Interface)
	assert.Equal(t, netip.MustParseAddrPort("192.0.2.1:68"), ev.Peer)
	assert.Equal(t, events.OutcomeParseError, ev.Outcome)
	assert.Equal(t, events.PathNone, ev.Path)
	assert.NotEmpty(t, ev.Error)
	// Nothing was decoded, so nothing about the client is known.
	assert.Empty(t, ev.Type)
	assert.Empty(t, ev.ClientID)
	assert.Empty(t, ev.ReplyType)
	assert.Zero(t, ev.Duration)
}

func TestHandleMsg4ObserverUnsupported(t *testing.T) {
	req := mustRequest4(t,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithOption(dhcpv4.OptHostName("client-1")),
		dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")),
	)
	req.OpCode = dhcpv4.OpcodeBootReply // buildReply4 rejects this

	l, obs := observedListener4(nil, &fakeConn4{})
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 67})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeUnsupported, ev.Outcome)
	assert.Equal(t, events.PathNone, ev.Path)
	assert.Contains(t, ev.Error, "unsupported opcode")
	// The packet parsed, so what it said about the client is reported.
	assert.Equal(t, "DISCOVER", ev.Type)
	assert.Equal(t, testMAC.String(), ev.ClientID)
	assert.Equal(t, "client-1", ev.Hostname)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), ev.Relay)
	assert.Empty(t, ev.ReplyType)
}

func TestHandleMsg4ObserverDropped(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	pass := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return resp, false }
	drop := func(_, _ *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) { return nil, true }

	l, obs := observedListener4([]handler.Handler4{pass, drop, pass}, &fakeConn4{})
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeDropped, ev.Outcome)
	assert.Equal(t, events.PathNone, ev.Path)
	assert.Equal(t, "plugin2", ev.Plugin)
	assert.Equal(t, 2, ev.Position)
	assert.Empty(t, ev.ReplyType)
	assert.Empty(t, ev.Addresses)
}

func TestHandleMsg4ObserverRepliedBroadcast(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast()
	lease := func(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		resp.YourIPAddr = net.IP{192, 0, 2, 10}
		resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(30 * time.Minute))
		return resp, false
	}

	l, obs := observedListener4([]handler.Handler4{lease}, &fakeConn4{})
	l.Index, l.Name = 5, "eth0"
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 68})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeReplied, ev.Outcome)
	assert.Equal(t, events.PathBroadcast, ev.Path)
	assert.Equal(t, "OFFER", ev.ReplyType)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}, ev.Addresses)
	assert.Equal(t, 30*time.Minute, ev.LeaseTime)
	// The whole chain ran, so no plugin is named.
	assert.Empty(t, ev.Plugin)
	assert.Zero(t, ev.Position)
	assert.Empty(t, ev.Error)
	assert.GreaterOrEqual(t, ev.Duration, time.Duration(0))
}

func TestHandleMsg4ObserverRepliedUnicastToRelay(t *testing.T) {
	req := mustRequest4(t,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")),
	)
	l, obs := observedListener4(nil, &fakeConn4{})
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 67})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeReplied, ev.Outcome)
	assert.Equal(t, events.PathUnicast, ev.Path)
	assert.Equal(t, "ACK", ev.ReplyType)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), ev.Relay)
	// No plugin handed out an address.
	assert.Empty(t, ev.Addresses)
	assert.Zero(t, ev.LeaseTime)
}

func TestHandleMsg4ObserverSendError(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	req.SetBroadcast()

	l, obs := observedListener4(nil, &fakeConn4{writeErr: errors.New("write boom")})
	l.Index, l.Name = 5, "eth0"
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeSendError, ev.Outcome)
	// Path and ReplyType say what the server tried to do.
	assert.Equal(t, events.PathBroadcast, ev.Path)
	assert.Equal(t, "OFFER", ev.ReplyType)
	assert.Equal(t, "write boom", ev.Error)
}

func TestHandleMsg4ObserverLayer2(t *testing.T) {
	loName := loopbackInterfaceName(t)
	lo, err := net.InterfaceByName(loName)
	require.NoError(t, err)

	// The default reply destination is a raw frame: no gateway, no client
	// address, no broadcast flag.
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))

	origSendEthernet := sendEthernetFn
	defer func() { sendEthernetFn = origSendEthernet }()

	cases := []struct {
		name        string
		boundIndex  int
		sendErr     error
		wantOutcome events.Outcome
		wantErr     string
	}{
		{
			name:        "sent",
			boundIndex:  lo.Index,
			wantOutcome: events.OutcomeReplied,
		},
		{
			name:        "no interface to send on",
			boundIndex:  0,
			wantOutcome: events.OutcomeSendError,
			wantErr:     errNoLayer2Interface.Error(),
		},
		{
			name:        "interface lookup fails",
			boundIndex:  999999,
			wantOutcome: events.OutcomeSendError,
			wantErr:     "no such network interface",
		},
		{
			name:        "send fails",
			boundIndex:  lo.Index,
			sendErr:     errors.New("send boom"),
			wantOutcome: events.OutcomeSendError,
			wantErr:     "send boom",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sendEthernetFn = func(net.Interface, *dhcpv4.DHCPv4) error { return tc.sendErr }
			l, obs := observedListener4(nil, &fakeConn4{})
			l.Index = tc.boundIndex
			l.HandleMsg4(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})

			ev := obs.only(t)
			assert.Equal(t, tc.wantOutcome, ev.Outcome)
			assert.Equal(t, events.PathLayer2, ev.Path)
			assert.Equal(t, "OFFER", ev.ReplyType)
			if tc.wantErr == "" {
				assert.Empty(t, ev.Error)
				return
			}
			assert.Contains(t, ev.Error, tc.wantErr)
		})
	}
}

// An unbound listener learns the interface from each packet's control
// message. The name is resolved once and then remembered, so a second packet
// from the same interface reports the same name without another lookup.
func TestHandleMsg4ObserverInterfaceFromControlMessage(t *testing.T) {
	loName := loopbackInterfaceName(t)
	lo, err := net.InterfaceByName(loName)
	require.NoError(t, err)

	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")))
	l, obs := observedListener4(nil, &fakeConn4{})
	peer := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 67}

	l.HandleMsg4(datagramBuf(req.ToBytes()), &ipv4.ControlMessage{IfIndex: lo.Index}, peer)
	l.HandleMsg4(datagramBuf(req.ToBytes()), &ipv4.ControlMessage{IfIndex: lo.Index}, peer)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	require.Len(t, obs.requests, 2)
	assert.Equal(t, loName, obs.requests[0].Interface)
	assert.Equal(t, loName, obs.requests[1].Interface)

	cached, ok := l.ifaces.names.Load(lo.Index)
	require.True(t, ok)
	assert.Equal(t, loName, cached)
}

// An index that does not resolve leaves the interface empty rather than
// guessing, and the failure is cached so the lookup is not retried per packet.
func TestHandleMsg4ObserverUnknownInterfaceIndex(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")))
	l, obs := observedListener4(nil, &fakeConn4{})
	l.HandleMsg4(datagramBuf(req.ToBytes()), &ipv4.ControlMessage{IfIndex: 999999}, &net.UDPAddr{IP: net.ParseIP("10.0.0.1")})

	assert.Empty(t, obs.only(t).Interface)
	cached, ok := l.ifaces.names.Load(999999)
	require.True(t, ok)
	assert.Empty(t, cached)
}

// A listener with no control message and no bound interface reports no
// interface at all.
func TestHandleMsg4ObserverNoInterfaceInformation(t *testing.T) {
	req := mustRequest4(t, dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithGatewayIP(net.ParseIP("10.0.0.1")))
	l, obs := observedListener4(nil, &fakeConn4{})
	l.HandleMsg4(datagramBuf(req.ToBytes()), nil, nil)

	ev := obs.only(t)
	assert.Empty(t, ev.Interface)
	assert.False(t, ev.Peer.IsValid())
}

func TestHandleMsg6ObserverParseError(t *testing.T) {
	l, obs := observedListener6(nil, &fakeConn6{})
	l.Index, l.Name = 7, "eth1"
	l.HandleMsg6(datagramBuf([]byte{0x01}), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 546})

	ev := obs.only(t)
	assert.Equal(t, events.FamilyV6, ev.Family)
	assert.Equal(t, "eth1", ev.Interface)
	assert.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:546"), ev.Peer)
	assert.Equal(t, events.OutcomeParseError, ev.Outcome)
	assert.Equal(t, events.PathNone, ev.Path)
	assert.NotEmpty(t, ev.Error)
}

func TestHandleMsg6ObserverUnsupported(t *testing.T) {
	req := message6(t, dhcpv6.MessageTypeAdvertise) // never accepted as a request
	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeUnsupported, ev.Outcome)
	assert.Equal(t, "ADVERTISE", ev.Type)
	assert.Equal(t, fixedDUIDHex, ev.ClientID)
	assert.Contains(t, ev.Error, "not supported")
	assert.Empty(t, ev.ReplyType)
}

func TestHandleMsg6ObserverDropped(t *testing.T) {
	req := message6(t, dhcpv6.MessageTypeRequest)
	drop := func(_, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) { return nil, true }

	l, obs := observedListener6([]handler.Handler6{drop}, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeDropped, ev.Outcome)
	assert.Equal(t, "plugin1", ev.Plugin)
	assert.Equal(t, 1, ev.Position)
	assert.Equal(t, "REQUEST", ev.Type)
	assert.Empty(t, ev.ReplyType)
}

// A relay-forward the server cannot answer with a relay-reply is reported as
// unsupported, with nothing said about a reply, because none went out.
func TestHandleMsg6ObserverEncapsulateError(t *testing.T) {
	inner := message6(t, dhcpv6.MessageTypeRequest)
	req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayReply, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)

	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeUnsupported, ev.Outcome)
	assert.Equal(t, events.PathNone, ev.Path)
	assert.NotEmpty(t, ev.Error)
	assert.Equal(t, "REQUEST", ev.Type)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), ev.Relay)
	assert.Empty(t, ev.ReplyType)
}

func TestHandleMsg6ObserverSendError(t *testing.T) {
	req := message6(t, dhcpv6.MessageTypeRequest)
	l, obs := observedListener6(nil, &fakeConn6{writeErr: errors.New("write boom")})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeSendError, ev.Outcome)
	assert.Equal(t, events.PathUnicast, ev.Path)
	assert.Equal(t, "REPLY", ev.ReplyType)
	assert.Equal(t, "write boom", ev.Error)
}

func TestHandleMsg6ObserverReplied(t *testing.T) {
	fqdn := &dhcpv6.OptFQDN{DomainName: &rfc1035label.Labels{Labels: []string{"client", "example", "com"}}}
	req := message6(t, dhcpv6.MessageTypeRequest, fqdn)

	assign := func(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
		msg, ok := resp.(*dhcpv6.Message)
		if !ok {
			return resp, true
		}
		msg.AddOption(&dhcpv6.OptIANA{
			IaId: [4]byte{1, 2, 3, 4},
			Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{
				&dhcpv6.OptIAAddress{
					IPv6Addr:          net.ParseIP("2001:db8::10"),
					PreferredLifetime: time.Hour,
					ValidLifetime:     2 * time.Hour,
				},
			}},
		})
		return resp, false
	}

	l, obs := observedListener6([]handler.Handler6{assign}, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 546})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeReplied, ev.Outcome)
	assert.Equal(t, events.PathUnicast, ev.Path)
	assert.Equal(t, "REQUEST", ev.Type)
	assert.Equal(t, "REPLY", ev.ReplyType)
	assert.Equal(t, fixedDUIDHex, ev.ClientID)
	assert.Equal(t, "client.example.com", ev.Hostname)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::10/128")}, ev.Addresses)
	assert.Equal(t, 2*time.Hour, ev.LeaseTime)
	assert.False(t, ev.Relay.IsValid())
}

// A relayed request reports the client from the inner message and the relay
// that forwarded it, and the reply is described after re-encapsulation.
func TestHandleMsg6ObserverRelayed(t *testing.T) {
	inner := message6(t, dhcpv6.MessageTypeRequest)
	req, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	require.NoError(t, err)

	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeReplied, ev.Outcome)
	assert.Equal(t, "REQUEST", ev.Type)
	assert.Equal(t, "REPLY", ev.ReplyType)
	assert.Equal(t, fixedDUIDHex, ev.ClientID)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), ev.Relay)
}

func TestHandleMsg6ObserverInterfaceFromControlMessage(t *testing.T) {
	loName := loopbackInterfaceName(t)
	lo, err := net.InterfaceByName(loName)
	require.NoError(t, err)

	req := message6(t, dhcpv6.MessageTypeRequest)
	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), &ipv6.ControlMessage{IfIndex: lo.Index}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	assert.Equal(t, loName, obs.only(t).Interface)
}

// A SOLICIT asking for rapid commit is answered with a REPLY instead of an
// ADVERTISE. Nothing in the chain hands out an address here, so the event
// reports a reply with no addresses and no lease time rather than zeroes that
// look like a lease.
func TestHandleMsg6ObserverRapidCommit(t *testing.T) {
	req := mustSolicit(t, true)
	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, events.OutcomeReplied, ev.Outcome)
	assert.Equal(t, "SOLICIT", ev.Type)
	assert.Equal(t, "REPLY", ev.ReplyType)
	assert.NotEmpty(t, ev.ClientID)
	assert.Empty(t, ev.Addresses)
	assert.Zero(t, ev.LeaseTime)
}

// Without rapid commit the same SOLICIT gets an ADVERTISE.
func TestHandleMsg6ObserverSolicitAdvertise(t *testing.T) {
	req := mustSolicit(t, false)
	l, obs := observedListener6(nil, &fakeConn6{})
	l.HandleMsg6(datagramBuf(req.ToBytes()), nil, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})

	ev := obs.only(t)
	assert.Equal(t, "SOLICIT", ev.Type)
	assert.Equal(t, "ADVERTISE", ev.ReplyType)
}
