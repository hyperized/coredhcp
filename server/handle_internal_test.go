// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"errors"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/coredhcp/coredhcp/handler"
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

	t.Run("empty chain returns resp unchanged", func(t *testing.T) {
		resp := applyHandlers4(nil, base, base)
		assert.Same(t, base, resp)
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
		resp := applyHandlers4([]handler.Handler4{h1, h2, h3}, base, base)
		assert.Nil(t, resp)
		assert.Equal(t, []int{1, 2}, order)
	})
}

func TestApplyHandlers6(t *testing.T) {
	base := mustSolicit(t, false)

	t.Run("empty chain returns resp unchanged", func(t *testing.T) {
		resp := applyHandlers6(nil, base, base)
		assert.Same(t, base, resp)
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
		resp := applyHandlers6([]handler.Handler6{h1, h2, h3}, base, base)
		assert.Nil(t, resp)
		assert.Equal(t, []int{1, 2}, order)
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
			peer, useEthernet := replyDestination4(tc.req, tc.resp)
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
	return &listener4{conn4: conn, handlers: handlers}
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
	return &listener6{conn6: conn, handlers: handlers}
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
