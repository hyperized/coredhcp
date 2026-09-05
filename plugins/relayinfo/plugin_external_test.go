// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package relayinfo_test

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins/relayinfo"
)

const clientMAC = "00:11:22:33:44:55"

// writeMappings writes a mapping file and returns the file: argument for it.
func writeMappings(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ports.txt")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return "file:" + path
}

func handler4(t *testing.T, key, contents string) handler.Handler4 {
	t.Helper()
	h, err := relayinfo.Plugin.Setup4(writeMappings(t, contents), "key:"+key)
	require.NoError(t, err)
	return h
}

func handler6(t *testing.T, key, contents string) handler.Handler6 {
	t.Helper()
	h, err := relayinfo.Plugin.Setup6(writeMappings(t, contents), "key:"+key)
	require.NoError(t, err)
	return h
}

// message4 builds a DHCPv4 request of the given type, with an option 82
// carrying subs, and the reply the server would hand to the plugin chain.
func message4(t *testing.T, mt dhcpv4.MessageType, subs ...dhcpv4.Option) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	mac, err := net.ParseMAC(clientMAC)
	require.NoError(t, err)
	req, err := dhcpv4.NewDiscovery(mac)
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptMessageType(mt))
	if len(subs) > 0 {
		req.UpdateOption(dhcpv4.OptRelayAgentInfo(subs...))
	}
	// NewReplyFromRequest copies option 82 into the reply on its own (RFC
	// 3046 section 2.2), which is why the plugin never echoes it.
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

// relayed6 wraps a Solicit in one relay message carrying opts, and returns it
// with the Advertise the chain gets alongside it.
func relayed6(t *testing.T, opts ...dhcpv6.Option) (*dhcpv6.RelayMessage, dhcpv6.DHCPv6) {
	t.Helper()
	inner := solicit6(t)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(inner)
	require.NoError(t, err)
	return encapsulate6(t, inner, opts...), resp
}

func solicit6(t *testing.T) *dhcpv6.Message {
	t.Helper()
	mac, err := net.ParseMAC(clientMAC)
	require.NoError(t, err)
	inner, err := dhcpv6.NewSolicit(mac)
	require.NoError(t, err)
	return inner
}

func encapsulate6(t *testing.T, inner dhcpv6.DHCPv6, opts ...dhcpv6.Option) *dhcpv6.RelayMessage {
	t.Helper()
	relay, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.IPv6loopback, net.IPv6loopback)
	require.NoError(t, err)
	for _, opt := range opts {
		relay.AddOption(opt)
	}
	return relay
}

// requireIAAddr pulls the single IA_NA address the plugin is expected to have
// added to result.
func requireIAAddr(t *testing.T, result dhcpv6.DHCPv6) *dhcpv6.OptIAAddress {
	t.Helper()
	opt := result.GetOneOption(dhcpv6.OptionIANA)
	require.NotNil(t, opt)
	iana, ok := opt.(*dhcpv6.OptIANA)
	require.True(t, ok)
	addrs := iana.Options.Addresses()
	require.Len(t, addrs, 1)
	return addrs[0]
}

// TestHandler4Keys checks that each of the three DHCPv4 keys is read from the
// sub-option it is named after, and only from that one.
func TestHandler4Keys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		code dhcpv4.OptionCode
	}{
		{name: "circuit-id", key: "circuit-id", code: dhcpv4.AgentCircuitIDSubOption},
		{name: "remote-id", key: "remote-id", code: dhcpv4.AgentRemoteIDSubOption},
		{name: "subscriber-id", key: "subscriber-id", code: dhcpv4.SubscriberIDSubOption},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := handler4(t, tc.key, "rack4-sw1:eth3 192.0.2.31 30m\n")

			t.Run("matched", func(t *testing.T) {
				req, resp := message4(t, dhcpv4.MessageTypeDiscover,
					dhcpv4.OptGeneric(tc.code, []byte("rack4-sw1:eth3")))
				result, stop := h(req, resp)
				require.NotNil(t, result)
				assert.True(t, stop, "a matched key ends the DHCPv4 chain")
				assert.Equal(t, "192.0.2.31", result.YourIPAddr.String())
				assert.Equal(t, 30*time.Minute, result.IPAddressLeaseTime(0))
			})

			t.Run("same value in another sub-option is not this key", func(t *testing.T) {
				other := dhcpv4.AgentCircuitIDSubOption
				if tc.code == other {
					other = dhcpv4.AgentRemoteIDSubOption
				}
				req, resp := message4(t, dhcpv4.MessageTypeDiscover,
					dhcpv4.OptGeneric(other, []byte("rack4-sw1:eth3")))
				result, stop := h(req, resp)
				assert.False(t, stop)
				assert.True(t, result.YourIPAddr.IsUnspecified())
			})
		})
	}
}

func TestHandler4(t *testing.T) {
	// longKey is exactly maxKeyLen bytes, the largest a mapping file takes
	// and the largest an option 82 sub-option can carry.
	longKey := "port-" + strings.Repeat("a", 250)
	mappings := "rack4-sw1:eth3 192.0.2.31 30m\n" +
		"0x0a0b0c 192.0.2.32\n" +
		longKey + " 192.0.2.33\n"

	circuit := func(value []byte) dhcpv4.Option {
		return dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, value)
	}

	for _, tc := range []struct {
		name      string
		subs      []dhcpv4.Option
		wantAddr  string
		wantLease time.Duration
	}{
		{
			name:      "hex key matches the raw bytes",
			subs:      []dhcpv4.Option{circuit([]byte{0x0a, 0x0b, 0x0c})},
			wantAddr:  "192.0.2.32",
			wantLease: time.Hour,
		},
		{
			name:      "key at the 255 byte limit",
			subs:      []dhcpv4.Option{circuit([]byte(longKey))},
			wantAddr:  "192.0.2.33",
			wantLease: time.Hour,
		},
		{name: "no relay agent information at all"},
		{name: "relay agent information without a circuit-id",
			subs: []dhcpv4.Option{dhcpv4.OptGeneric(dhcpv4.AgentRemoteIDSubOption, []byte("rack4-sw1:eth3"))}},
		{name: "circuit-id that is not mapped", subs: []dhcpv4.Option{circuit([]byte("rack9-sw1:eth1"))}},
		{name: "empty circuit-id", subs: []dhcpv4.Option{circuit(nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := handler4(t, "circuit-id", mappings)
			req, resp := message4(t, dhcpv4.MessageTypeDiscover, tc.subs...)
			result, stop := h(req, resp)
			require.NotNil(t, result)

			if tc.wantAddr == "" {
				assert.False(t, stop, "an unmatched request continues the chain")
				assert.True(t, result.YourIPAddr.IsUnspecified())
				assert.Zero(t, result.IPAddressLeaseTime(0))
				return
			}
			assert.True(t, stop)
			assert.Equal(t, tc.wantAddr, result.YourIPAddr.String())
			assert.Equal(t, tc.wantLease, result.IPAddressLeaseTime(0))
		})
	}
}

// TestHandler4PassesThroughMessageTypes covers the message types the plugin
// must not answer even when the key is mapped. The server sends no reply at
// all to a RELEASE or a DECLINE, so the handler is also given a nil response
// to prove it does not touch one.
func TestHandler4PassesThroughMessageTypes(t *testing.T) {
	h := handler4(t, "circuit-id", "rack4-sw1:eth3 192.0.2.31\n")

	for _, mt := range []dhcpv4.MessageType{
		dhcpv4.MessageTypeRelease,
		dhcpv4.MessageTypeDecline,
		dhcpv4.MessageTypeInform,
	} {
		t.Run(mt.String(), func(t *testing.T) {
			req, resp := message4(t, mt, dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("rack4-sw1:eth3")))
			result, stop := h(req, resp)
			assert.False(t, stop)
			require.NotNil(t, result)
			assert.True(t, result.YourIPAddr.IsUnspecified())
			assert.Zero(t, result.IPAddressLeaseTime(0))

			req, _ = message4(t, mt, dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("rack4-sw1:eth3")))
			result, stop = h(req, nil)
			assert.False(t, stop)
			assert.Nil(t, result)
		})
	}
}

func TestHandler6InterfaceID(t *testing.T) {
	h := handler6(t, "interface-id", "rack4-sw1:eth3 2001:db8::31 12h\n0x0004010203 2001:db8::32\n")

	for _, tc := range []struct {
		name      string
		opts      []dhcpv6.Option
		wantAddr  string
		wantLease time.Duration
	}{
		{
			name:      "text interface-id",
			opts:      []dhcpv6.Option{dhcpv6.OptInterfaceID([]byte("rack4-sw1:eth3"))},
			wantAddr:  "2001:db8::31",
			wantLease: 12 * time.Hour,
		},
		{
			name:      "binary interface-id",
			opts:      []dhcpv6.Option{dhcpv6.OptInterfaceID([]byte{0x00, 0x04, 0x01, 0x02, 0x03})},
			wantAddr:  "2001:db8::32",
			wantLease: time.Hour,
		},
		{name: "no interface-id"},
		{name: "interface-id that is not mapped",
			opts: []dhcpv6.Option{dhcpv6.OptInterfaceID([]byte("rack9-sw1:eth1"))}},
		{
			// A relay is free to send an interface-id this long. It cannot be
			// written in a mapping file, so it is passed on without a lookup.
			name: "interface-id over the 255 byte limit",
			opts: []dhcpv6.Option{dhcpv6.OptInterfaceID([]byte(strings.Repeat("a", 256)))},
		},
		{name: "a remote-id is not an interface-id",
			opts: []dhcpv6.Option{&dhcpv6.OptRemoteID{EnterpriseNumber: 9, RemoteID: []byte("rack4-sw1:eth3")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := relayed6(t, tc.opts...)
			result, stop := h(req, resp)
			require.NotNil(t, result)
			assert.False(t, stop, "the DHCPv6 chain always continues")

			if tc.wantAddr == "" {
				assert.Nil(t, result.GetOneOption(dhcpv6.OptionIANA))
				return
			}
			addr := requireIAAddr(t, result)
			assert.Equal(t, tc.wantAddr, addr.IPv6Addr.String())
			assert.Equal(t, tc.wantLease, addr.PreferredLifetime)
			assert.Equal(t, tc.wantLease, addr.ValidLifetime)

			inner, err := req.GetInnerMessage()
			require.NoError(t, err)
			iana, ok := result.GetOneOption(dhcpv6.OptionIANA).(*dhcpv6.OptIANA)
			require.True(t, ok)
			assert.Equal(t, inner.Options.OneIANA().IaId, iana.IaId, "the IA_NA must answer the IAID the client asked with")
		})
	}
}

// TestHandler6RemoteID also pins down that the enterprise number is not part
// of the key: only the identifier bytes after it are matched.
func TestHandler6RemoteID(t *testing.T) {
	h := handler6(t, "remote-id", "0xaabbccddeeff 2001:db8::41 4h\n")

	for _, tc := range []struct {
		name     string
		opts     []dhcpv6.Option
		wantAddr string
	}{
		{
			name:     "matched",
			opts:     []dhcpv6.Option{&dhcpv6.OptRemoteID{EnterpriseNumber: 4491, RemoteID: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}},
			wantAddr: "2001:db8::41",
		},
		{
			name:     "another enterprise number, same remote-id",
			opts:     []dhcpv6.Option{&dhcpv6.OptRemoteID{EnterpriseNumber: 9, RemoteID: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}},
			wantAddr: "2001:db8::41",
		},
		{name: "no remote-id", opts: []dhcpv6.Option{dhcpv6.OptInterfaceID([]byte("eth3"))}},
		{name: "remote-id that is not mapped",
			opts: []dhcpv6.Option{&dhcpv6.OptRemoteID{EnterpriseNumber: 4491, RemoteID: []byte{0x00}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := relayed6(t, tc.opts...)
			result, stop := h(req, resp)
			require.NotNil(t, result)
			assert.False(t, stop)

			if tc.wantAddr == "" {
				assert.Nil(t, result.GetOneOption(dhcpv6.OptionIANA))
				return
			}
			assert.Equal(t, tc.wantAddr, requireIAAddr(t, result).IPv6Addr.String())
		})
	}
}

// TestHandler6NestedRelays checks which relay wins when a request crosses
// more than one: the outermost, the one that handed the request to this
// server.
func TestHandler6NestedRelays(t *testing.T) {
	h := handler6(t, "interface-id", "access-sw:eth3 2001:db8::51\naggregation:xe-0/0/1 2001:db8::52\n")

	inner := solicit6(t)
	resp, err := dhcpv6.NewAdvertiseFromSolicit(inner)
	require.NoError(t, err)

	access := encapsulate6(t, inner, dhcpv6.OptInterfaceID([]byte("access-sw:eth3")))
	aggregation := encapsulate6(t, access, dhcpv6.OptInterfaceID([]byte("aggregation:xe-0/0/1")))

	result, stop := h(aggregation, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Equal(t, "2001:db8::52", requireIAAddr(t, result).IPv6Addr.String())
}

func TestHandler6PassesThrough(t *testing.T) {
	h := handler6(t, "interface-id", "rack4-sw1:eth3 2001:db8::31\n")
	iid := dhcpv6.OptInterfaceID([]byte("rack4-sw1:eth3"))

	t.Run("release and decline", func(t *testing.T) {
		for _, mt := range []dhcpv6.MessageType{dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline} {
			t.Run(mt.String(), func(t *testing.T) {
				inner := solicit6(t)
				inner.MessageType = mt
				resp, err := dhcpv6.NewMessage()
				require.NoError(t, err)
				resp.MessageType = dhcpv6.MessageTypeReply

				result, stop := h(encapsulate6(t, inner, iid), resp)
				require.NotNil(t, result)
				assert.False(t, stop)
				assert.Nil(t, result.GetOneOption(dhcpv6.OptionIANA))
			})
		}
	})

	t.Run("no address requested", func(t *testing.T) {
		inner := solicit6(t)
		inner.Options.Del(dhcpv6.OptionIANA)
		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp.MessageType = dhcpv6.MessageTypeAdvertise

		result, stop := h(encapsulate6(t, inner, iid), resp)
		require.NotNil(t, result)
		assert.False(t, stop)
		assert.Nil(t, result.GetOneOption(dhcpv6.OptionIANA))
	})

	t.Run("request did not come through a relay", func(t *testing.T) {
		inner := solicit6(t)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(inner)
		require.NoError(t, err)

		result, stop := h(inner, resp)
		require.NotNil(t, result)
		assert.False(t, stop)
		assert.Nil(t, result.GetOneOption(dhcpv6.OptionIANA))
	})

	t.Run("malformed relay message", func(t *testing.T) {
		// A RelayMessage with no embedded OptionRelayMsg makes
		// GetInnerMessage fail, which drops the request.
		req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		result, stop := h(req, nil)
		assert.Nil(t, result)
		assert.True(t, stop)
	})
}

func TestSetupErrors(t *testing.T) {
	valid := "rack4-sw1:eth3 192.0.2.31\n"

	for _, tc := range []struct {
		name    string
		args    []string
		errText string
	}{
		{name: "no arguments", errText: "need a mapping file"},
		{name: "no key", args: []string{"file:ports.txt"}, errText: "need a key to match on"},
		{name: "unknown argument", args: []string{"file:ports.txt", "key:circuit-id", "reload"},
			errText: "unexpected argument `reload`"},
		{name: "a DHCPv6 key in a server4 section", args: []string{"file:ports.txt", "key:interface-id"},
			errText: "unknown DHCPv4 key `interface-id`"},
		{name: "misspelled key", args: []string{"file:ports.txt", "key:circuitid"},
			errText: "unknown DHCPv4 key `circuitid`"},
		{name: "missing file", args: []string{"file:/nonexistent/ports.txt", "key:circuit-id"},
			errText: "no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := relayinfo.Plugin.Setup4(tc.args...)
			require.Error(t, err)
			assert.Nil(t, h)
			assert.Contains(t, err.Error(), tc.errText)
		})
	}

	t.Run("a DHCPv4 key in a server6 section", func(t *testing.T) {
		h, err := relayinfo.Plugin.Setup6(writeMappings(t, valid), "key:subscriber-id")
		require.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "unknown DHCPv6 key `subscriber-id`")
	})

	t.Run("the parse error names the file and the line", func(t *testing.T) {
		fileArg := writeMappings(t, "rack4-sw1:eth3 192.0.2.31\nrack4-sw1:eth4 not-an-address\n")
		h, err := relayinfo.Plugin.Setup4(fileArg, "key:circuit-id")
		require.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), strings.TrimPrefix(fileArg, "file:"))
		assert.Contains(t, err.Error(), "line 2: expected an IPv4 address")
	})

	t.Run("a mapping file for the other family", func(t *testing.T) {
		h, err := relayinfo.Plugin.Setup6(writeMappings(t, valid), "key:interface-id")
		require.Error(t, err)
		assert.Nil(t, h)
		assert.Contains(t, err.Error(), "expected an IPv6 address")
	})
}

// TestAutorefresh exercises the full autorefresh lifecycle: the initial load,
// picking up a valid update, surviving a malformed update without losing the
// mappings that were already loaded, and recovering once a valid file is
// written again. All waits are require.Eventually against directly observable
// state rather than fixed sleeps: handler responses, and the logged warning
// for the otherwise invisible failed-reload case.
func TestAutorefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports.txt")
	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.31\n"), 0o600))

	logPath := filepath.Join(dir, "plugin.log")
	require.NoError(t, logger.WithFile(logPath))
	t.Cleanup(func() { _ = logger.WithFile(os.DevNull) })

	h, err := relayinfo.Plugin.Setup4("file:"+path, "key:circuit-id", "autorefresh")
	require.NoError(t, err)

	resolves := func(key string) func() bool {
		return func() bool {
			req, resp := message4(t, dhcpv4.MessageTypeDiscover,
				dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte(key)))
			result, _ := h(req, resp)
			return !result.YourIPAddr.IsUnspecified()
		}
	}

	require.True(t, resolves("port-1")(), "the initial mapping must resolve right after setup")

	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.31\nport-2 192.0.2.32\n"), 0o600))
	require.Eventually(t, resolves("port-2"), 5*time.Second, 20*time.Millisecond,
		"autorefresh did not pick up the newly added mapping")

	// A malformed update must fail the reload (logging a warning) without
	// disturbing the mappings already loaded. It is written in place rather
	// than with os.WriteFile, which truncates first: the watcher can reload
	// between the truncate and the write, and an empty file is a valid file
	// with no mappings, so the mappings would be gone before the bad content
	// ever landed.
	overwrite(t, path, "port-1 this-is-not-an-address\n")
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(logPath)
		return err == nil && strings.Contains(string(data), "failed to refresh from")
	}, 5*time.Second, 20*time.Millisecond, "expected a refresh-failure warning to be logged")
	assert.True(t, resolves("port-1")(), "a mapping must keep resolving after a bad reload")
	assert.True(t, resolves("port-2")(), "a mapping must keep resolving after a bad reload")

	// The watcher goroutine must still be running after the failed reload, so
	// a further valid update is picked up too.
	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.31\nport-3 192.0.2.33\n"), 0o600))
	require.Eventually(t, resolves("port-3"), 5*time.Second, 20*time.Millisecond,
		"autorefresh did not recover after a bad reload")
}

// overwrite replaces the start of path with data without truncating it, so a
// watcher never sees the file empty. What was there before stays on after the
// new content, which is fine for content that is meant to be malformed.
func overwrite(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte(data), 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
