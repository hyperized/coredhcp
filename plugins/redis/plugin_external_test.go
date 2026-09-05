// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpiana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/redis"
)

var (
	testMAC    = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	unknownMAC = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
)

// fakeRedis is a minimal RESP2 server, just enough of the protocol for this
// plugin's PING, AUTH, SELECT and HGETALL to get real replies over a real
// socket instead of a mock of the client.
type fakeRedis struct {
	addr string

	mu     sync.Mutex
	hashes map[string]map[string]string
	raw    string // when set, HGETALL replies with this instead of a hash
	conns  []net.Conn
	calls  int // every command received, PING included
}

// newFakeRedis starts the server and ties its shutdown, connections and
// goroutines included, to the test's cleanup.
func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeRedis{addr: ln.Addr().String(), hashes: map[string]map[string]string{}}
	var accepting, serving sync.WaitGroup
	accepting.Add(1)
	go func() {
		defer accepting.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, conn)
			f.mu.Unlock()
			serving.Add(1)
			go func() {
				defer serving.Done()
				f.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		// Wait for the accept loop to stop before walking the connection
		// list, otherwise a connection accepted at just the wrong moment is
		// never closed and the wait below never returns. Closing every
		// connection is what unblocks the reads serve is parked on: the
		// client behind a handler has no Close a test can reach.
		require.NoError(t, ln.Close())
		accepting.Wait()
		f.mu.Lock()
		for _, c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		serving.Wait()
	})
	return f
}

func (f *fakeRedis) setHash(key string, fields map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashes[key] = fields
}

func (f *fakeRedis) setRaw(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw = raw
}

func (f *fakeRedis) serve(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if _, err := conn.Write(f.reply(args)); err != nil {
			return
		}
	}
}

// readRESPCommand parses one RESP array of bulk strings, the only shape a
// real redis client sends a command as.
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	n, err := readRESPCount(r, '*')
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		l, err := readRESPCount(r, '$')
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args[i] = string(buf[:l])
	}
	return args, nil
}

// readRESPCount reads a line of the form "<want><digits>\r\n" and returns
// the digits, used for both the array length and each bulk string length.
func readRESPCount(r *bufio.Reader, want byte) (int, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 2 || line[0] != want {
		return 0, fmt.Errorf("unexpected RESP line %q", line)
	}
	return strconv.Atoi(line[1:])
}

// callCount returns the number of commands the server has received, so a
// test can assert that a message the plugin is meant to pass on never reached
// the backend at all.
func (f *fakeRedis) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// reply builds the RESP2 reply for one command. Redis command names are
// case insensitive, so args[0] is upper-cased before matching.
func (f *fakeRedis) reply(args []string) []byte {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if len(args) == 0 {
		return []byte("-ERR unknown command\r\n")
	}
	switch strings.ToUpper(args[0]) {
	case "PING":
		return []byte("+PONG\r\n")
	case "AUTH", "SELECT":
		return []byte("+OK\r\n")
	case "HGETALL":
		return f.hgetallReply(args)
	default:
		return []byte("-ERR unknown command\r\n")
	}
}

func (f *fakeRedis) hgetallReply(args []string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.raw != "" {
		return []byte(f.raw)
	}
	fields := f.hashes[args[len(args)-1]]
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", 2*len(fields))
	for name, value := range fields {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n$%d\r\n%s\r\n", len(name), name, len(value), value)
	}
	return b.Bytes()
}

// unreachableAddr returns a host:port nothing listens on, to exercise the
// "redis is unreachable" path without depending on a specific reserved port
// being refused the same way on every platform.
func unreachableAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// macKey mirrors the plugin's default "mac:" prefix, so fixtures written
// through setHash land under the key the handlers will look up.
func macKey(mac net.HardwareAddr) string {
	return "mac:" + mac.String()
}

// onlyRequest replaces the parameter request list built by
// dhcpv4.NewDiscovery, which always asks for the DNS option among others. A
// request with no list at all is not the same thing: RFC 2131 section 3.5
// reads that as asking for everything, and the plugin follows the library in
// honouring it.
func onlyRequest(codes ...dhcpv4.OptionCode) dhcpv4.Modifier {
	return func(d *dhcpv4.DHCPv4) {
		d.UpdateOption(dhcpv4.OptParameterRequestList(codes...))
	}
}

func v4Discover(t *testing.T, mac net.HardwareAddr, modifiers ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.NewDiscovery(mac, modifiers...)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	return req, resp
}

func v6Request(t *testing.T, modifiers ...dhcpv6.Modifier) (dhcpv6.DHCPv6, dhcpv6.DHCPv6) {
	t.Helper()
	req, err := dhcpv6.NewMessage(modifiers...)
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	return req, resp
}

// requireIAAddr pulls the single IA_NA address the plugin is expected to
// have added to result.
func requireIAAddr(t *testing.T, result dhcpv6.DHCPv6) *dhcpv6.OptIAAddress {
	t.Helper()
	opt := result.GetOneOption(dhcpv6.OptionIANA)
	require.NotNil(t, opt)
	ianaOpt, ok := opt.(*dhcpv6.OptIANA)
	require.True(t, ok)
	addrs := ianaOpt.Options.Addresses()
	require.Len(t, addrs, 1)
	return addrs[0]
}

func TestSetupErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"address is neither host:port nor a URL", []string{"not-a-valid-address"}},
		{"bad port", []string{"127.0.0.1:notaport"}},
		{"unsupported URL scheme", []string{"http://127.0.0.1:6379"}},
		{"URL with no host", []string{"redis://"}},
		{"bad /db path", []string{"redis://127.0.0.1:6379/notanumber"}},
		{"invalid timeout", []string{"127.0.0.1:6379", "timeout:notaduration"}},
		{"non-positive timeout", []string{"127.0.0.1:6379", "timeout:0s"}},
		{"invalid lifetime", []string{"127.0.0.1:6379", "lifetime:notaduration"}},
		{"non-positive lifetime", []string{"127.0.0.1:6379", "lifetime:0h"}},
		{"password with no value", []string{"127.0.0.1:6379", "password:"}},
		{"password env unset", []string{"127.0.0.1:6379", "password:env:COREDHCP_TEST_REDIS_UNSET_VAR"}},
		{"unknown trailing argument", []string{"127.0.0.1:6379", "bogus:1"}},
		{"unknown key mode", []string{"127.0.0.1:6379", "key:bogus"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := redis.Plugin.Setup4(tc.args...)
			assert.Error(t, err)

			_, err = redis.Plugin.Setup6(tc.args...)
			assert.Error(t, err)
		})
	}

	t.Run("password env empty", func(t *testing.T) {
		t.Setenv("COREDHCP_TEST_REDIS_EMPTY_VAR", "")
		_, err := redis.Plugin.Setup4("127.0.0.1:6379", "password:env:COREDHCP_TEST_REDIS_EMPTY_VAR")
		assert.Error(t, err)
	})
}

// TestSetupKeyModeFamilies pins the family rule down through the public
// surface, because it is a config-file contract and not an implementation
// detail: a DHCPv4 client has no DUID and DHCPv6 has no option 61, so asking
// for either under the wrong server section has to fail at startup instead of
// silently matching no client at all.
func TestSetupKeyModeFamilies(t *testing.T) {
	addr := unreachableAddr(t)

	cases := []struct {
		name    string
		key     string
		wantErr bool
		v6      bool
	}{
		{name: "mac under server4", key: "key:mac"},
		{name: "mac under server6", key: "key:mac", v6: true},
		{name: "client-id under server4", key: "key:client-id"},
		{name: "duid under server6", key: "key:duid", v6: true},
		{name: "duid under server4 is refused", key: "key:duid", wantErr: true},
		{name: "client-id under server6 is refused", key: "key:client-id", v6: true, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.v6 {
				_, err = redis.Plugin.Setup6(addr, tc.key)
			} else {
				_, err = redis.Plugin.Setup4(addr, tc.key)
			}
			if !tc.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.key)
		})
	}
}

func TestSetup4PingFailureIsOnlyAWarning(t *testing.T) {
	// A database that is briefly down must not stop coredhcp from starting
	// and serving its other plugins, so a failed PING is logged and setup
	// still succeeds with a handler that works, not a stub.
	h4, err := redis.Plugin.Setup4(unreachableAddr(t))
	require.NoError(t, err)
	require.NotNil(t, h4)

	req, resp := v4Discover(t, testMAC)
	gotResp, stop := h4(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)
}

func TestSetup6PingFailureIsOnlyAWarning(t *testing.T) {
	h6, err := redis.Plugin.Setup6(unreachableAddr(t))
	require.NoError(t, err)
	require.NotNil(t, h6)

	duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, resp := v6Request(t, dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
	gotResp, stop := h6(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)
}

func TestHandler4Inform(t *testing.T) {
	// An unreachable backend proves the point: if INFORM touched redis at
	// all, the lookup would fail and the request would be dropped.
	h4, err := redis.Plugin.Setup4(unreachableAddr(t))
	require.NoError(t, err)

	req, err := dhcpv4.NewInform(testMAC, net.IPv4(10, 0, 0, 5))
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	gotResp, stop := h4(req, resp)
	assert.Same(t, resp, gotResp)
	assert.False(t, stop)
}

// TestHandler4SkipsLookupForReleaseAndDecline covers the messages coredhcp
// never answers: the plugin has to pass them on without spending a Redis
// round trip that an unauthenticated sender could otherwise trigger at will.
func TestHandler4SkipsLookupForReleaseAndDecline(t *testing.T) {
	for _, mtype := range []dhcpv4.MessageType{dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline} {
		t.Run(mtype.String(), func(t *testing.T) {
			f := newFakeRedis(t)
			h4, err := redis.Plugin.Setup4(f.addr)
			require.NoError(t, err)
			before := f.callCount() // Setup4 already sent one PING.

			req, err := dhcpv4.New(dhcpv4.WithHwAddr(testMAC), dhcpv4.WithMessageType(mtype))
			require.NoError(t, err)
			resp, err := dhcpv4.NewReplyFromRequest(req)
			require.NoError(t, err)

			gotResp, stop := h4(req, resp)
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
			assert.Equal(t, before, f.callCount(), "the lookup must not run for a message coredhcp never replies to")
		})
	}
}

func TestHandler4UnknownOrIncompleteMAC(t *testing.T) {
	cases := []struct {
		name   string
		mac    net.HardwareAddr
		fields map[string]string
	}{
		{"unknown MAC passes", unknownMAC, nil},
		{"hash without ipv4 passes", testMAC, map[string]string{"router": "10.0.0.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRedis(t)
			if tc.fields != nil {
				f.setHash(macKey(tc.mac), tc.fields)
			}
			h4, err := redis.Plugin.Setup4(f.addr)
			require.NoError(t, err)

			req, resp := v4Discover(t, tc.mac)
			gotResp, stop := h4(req, resp)
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
		})
	}
}

func TestHandler4UnparseableIPv4Drops(t *testing.T) {
	f := newFakeRedis(t)
	f.setHash(macKey(testMAC), map[string]string{"ipv4": "not-an-ip"})
	h4, err := redis.Plugin.Setup4(f.addr)
	require.NoError(t, err)

	req, resp := v4Discover(t, testMAC)
	gotResp, stop := h4(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)
}

func TestHandler4BackendError(t *testing.T) {
	cases := []struct {
		name string
		addr func(t *testing.T) string
	}{
		{"redis is unreachable", unreachableAddr},
		{"redis replies with an error", func(t *testing.T) string {
			t.Helper()
			f := newFakeRedis(t)
			f.setRaw("-ERR something broke\r\n")
			return f.addr
		}},
		{"redis replies with something HGETALL cannot parse", func(t *testing.T) string {
			t.Helper()
			f := newFakeRedis(t)
			f.setRaw("+OK\r\n")
			return f.addr
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := redis.Plugin.Setup4(tc.addr(t))
			require.NoError(t, err)

			req, resp := v4Discover(t, testMAC)
			gotResp, stop := h4(req, resp)
			assert.Nil(t, gotResp)
			assert.True(t, stop)
		})
	}
}

func TestHandler4Lease(t *testing.T) {
	cases := []struct {
		name       string
		fields     map[string]string
		requestDNS bool
		check      func(t *testing.T, resp *dhcpv4.DHCPv4)
	}{
		{
			name:   "bare ipv4 sets YourIPAddr and no subnet mask",
			fields: map[string]string{"ipv4": "10.0.0.5"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
				assert.Nil(t, resp.SubnetMask())
			},
		},
		{
			name:   "CIDR ipv4 also sets the subnet mask",
			fields: map[string]string{"ipv4": "10.0.0.5/24"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
				assert.Equal(t, net.CIDRMask(24, 32), resp.SubnetMask())
			},
		},
		{
			name:   "a valid router is added",
			fields: map[string]string{"ipv4": "10.0.0.5", "router": "10.0.0.1"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				require.Len(t, resp.Router(), 1)
				assert.Equal(t, "10.0.0.1", resp.Router()[0].String())
			},
		},
		{
			name:   "an invalid router is skipped, the rest of the lease still goes out",
			fields: map[string]string{"ipv4": "10.0.0.5", "router": "not-an-ip"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, "10.0.0.5", resp.YourIPAddr.String())
				assert.Empty(t, resp.Router())
			},
		},
		{
			name:       "dns is added when requested and an ipv4 entry exists",
			fields:     map[string]string{"ipv4": "10.0.0.5", "dns": "10.0.0.2,2001:db8::53"},
			requestDNS: true,
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				require.Len(t, resp.DNS(), 1)
				assert.Equal(t, "10.0.0.2", resp.DNS()[0].String())
			},
		},
		{
			name:       "dns is omitted when it was not requested",
			fields:     map[string]string{"ipv4": "10.0.0.5", "dns": "10.0.0.2"},
			requestDNS: false,
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.DNS())
			},
		},
		{
			name:       "dns is omitted when the field has no ipv4 entry",
			fields:     map[string]string{"ipv4": "10.0.0.5", "dns": "2001:db8::53"},
			requestDNS: true,
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Empty(t, resp.DNS())
			},
		},
		{
			name:   "leaseTime becomes the lease time option",
			fields: map[string]string{"ipv4": "10.0.0.5", "leaseTime": "12h"},
			check: func(t *testing.T, resp *dhcpv4.DHCPv4) {
				t.Helper()
				assert.Equal(t, 12*time.Hour, resp.IPAddressLeaseTime(0))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRedis(t)
			f.setHash(macKey(testMAC), tc.fields)
			h4, err := redis.Plugin.Setup4(f.addr)
			require.NoError(t, err)

			var modifiers []dhcpv4.Modifier
			if !tc.requestDNS {
				modifiers = append(modifiers, onlyRequest(dhcpv4.OptionSubnetMask))
			}
			req, resp := v4Discover(t, testMAC, modifiers...)
			gotResp, stop := h4(req, resp)
			require.Same(t, resp, gotResp)
			require.True(t, stop)
			tc.check(t, gotResp)
		})
	}
}

func TestHandler6RelayCannotDecapsulate(t *testing.T) {
	h6, err := redis.Plugin.Setup6(unreachableAddr(t))
	require.NoError(t, err)

	// A relay message with no embedded RelayMsg option is malformed: there
	// is nothing to decapsulate, and that is a bug in whatever sent it, not
	// something redis can be asked about.
	req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	gotResp, stop := h6(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)
}

// TestHandler6SkipsLookupForReleaseAndDecline covers the messages coredhcp
// never answers, both sent directly and behind a relay: the plugin has to
// read the inner message's type, since a relayed message carries the
// client's real type inside the RELAY-FORW envelope, not the outer one.
func TestHandler6SkipsLookupForReleaseAndDecline(t *testing.T) {
	for _, mtype := range []dhcpv6.MessageType{dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline} {
		t.Run(mtype.String(), func(t *testing.T) {
			f := newFakeRedis(t)
			f.setHash(macKey(testMAC), map[string]string{"ipv6": "2001:db8::10:1"})
			h6, err := redis.Plugin.Setup6(f.addr)
			require.NoError(t, err)
			before := f.callCount() // Setup6 already sent one PING.

			duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
			req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
			require.NoError(t, err)
			req.MessageType = mtype
			resp, err := dhcpv6.NewMessage()
			require.NoError(t, err)
			resp.MessageType = dhcpv6.MessageTypeReply

			gotResp, stop := h6(req, resp)
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
			assert.Equal(t, before, f.callCount(), "the lookup must not run for a message coredhcp never replies to")
		})

		t.Run(mtype.String()+" relayed", func(t *testing.T) {
			f := newFakeRedis(t)
			f.setHash(macKey(testMAC), map[string]string{"ipv6": "2001:db8::10:1"})
			h6, err := redis.Plugin.Setup6(f.addr)
			require.NoError(t, err)
			before := f.callCount() // Setup6 already sent one PING.

			duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
			inner, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
			require.NoError(t, err)
			inner.MessageType = mtype
			relayed, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward,
				net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
			require.NoError(t, err)
			resp, err := dhcpv6.NewMessage()
			require.NoError(t, err)
			resp.MessageType = dhcpv6.MessageTypeReply

			gotResp, stop := h6(relayed, resp)
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
			assert.Equal(t, before, f.callCount(), "a relayed message must be read for its inner type, not the outer RELAY-FORW")
		})
	}
}

func TestHandler6NoIANA(t *testing.T) {
	h6, err := redis.Plugin.Setup6(unreachableAddr(t))
	require.NoError(t, err)

	duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, resp := v6Request(t, dhcpv6.WithClientID(duid))
	gotResp, stop := h6(req, resp)
	assert.Same(t, resp, gotResp)
	assert.False(t, stop)
}

func TestHandler6NoMAC(t *testing.T) {
	h6, err := redis.Plugin.Setup6(unreachableAddr(t))
	require.NoError(t, err)

	// WithIANA and no ClientID: an address is requested, but ExtractMAC has
	// no DUID-LL/DUID-LLT or relay link-layer option to derive a MAC from.
	req, resp := v6Request(t, dhcpv6.WithIANA())
	gotResp, stop := h6(req, resp)
	assert.Same(t, resp, gotResp)
	assert.False(t, stop)
}

func TestHandler6UnknownOrIncompleteMAC(t *testing.T) {
	cases := []struct {
		name   string
		mac    net.HardwareAddr
		fields map[string]string
	}{
		{"unknown MAC passes", unknownMAC, nil},
		{"hash without ipv6 passes", testMAC, map[string]string{"ipv4": "10.0.0.5"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRedis(t)
			if tc.fields != nil {
				f.setHash(macKey(tc.mac), tc.fields)
			}
			h6, err := redis.Plugin.Setup6(f.addr)
			require.NoError(t, err)

			duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: tc.mac}
			req, resp := v6Request(t, dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
			gotResp, stop := h6(req, resp)
			assert.Same(t, resp, gotResp)
			assert.False(t, stop)
		})
	}
}

func TestHandler6UnparseableIPv6Drops(t *testing.T) {
	f := newFakeRedis(t)
	f.setHash(macKey(testMAC), map[string]string{"ipv6": "not-an-ip"})
	h6, err := redis.Plugin.Setup6(f.addr)
	require.NoError(t, err)

	duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, resp := v6Request(t, dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
	gotResp, stop := h6(req, resp)
	assert.Nil(t, gotResp)
	assert.True(t, stop)
}

func TestHandler6BackendError(t *testing.T) {
	cases := []struct {
		name string
		addr func(t *testing.T) string
	}{
		{"redis is unreachable", unreachableAddr},
		{"redis replies with an error", func(t *testing.T) string {
			t.Helper()
			f := newFakeRedis(t)
			f.setRaw("-ERR something broke\r\n")
			return f.addr
		}},
		{"redis replies with something HGETALL cannot parse", func(t *testing.T) string {
			t.Helper()
			f := newFakeRedis(t)
			f.setRaw("+OK\r\n")
			return f.addr
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h6, err := redis.Plugin.Setup6(tc.addr(t))
			require.NoError(t, err)

			duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
			req, resp := v6Request(t, dhcpv6.WithClientID(duid), dhcpv6.WithIANA())
			gotResp, stop := h6(req, resp)
			assert.Nil(t, gotResp)
			assert.True(t, stop)
		})
	}
}

func TestHandler6Lease(t *testing.T) {
	cases := []struct {
		name       string
		setupArgs  []string
		fields     map[string]string
		requestDNS bool
		check      func(t *testing.T, resp dhcpv6.DHCPv6)
	}{
		{
			name:   "leaseTime sets preferred and valid lifetime",
			fields: map[string]string{"ipv6": "2001:db8::5", "leaseTime": "2h"},
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				addr := requireIAAddr(t, resp)
				assert.Equal(t, "2001:db8::5", addr.IPv6Addr.String())
				assert.Equal(t, 2*time.Hour, addr.PreferredLifetime)
				assert.Equal(t, 2*time.Hour, addr.ValidLifetime)
			},
		},
		{
			name:      "missing leaseTime falls back to the lifetime argument",
			setupArgs: []string{"lifetime:30m"},
			fields:    map[string]string{"ipv6": "2001:db8::5"},
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				addr := requireIAAddr(t, resp)
				assert.Equal(t, 30*time.Minute, addr.PreferredLifetime)
				assert.Equal(t, 30*time.Minute, addr.ValidLifetime)
			},
		},
		{
			name:   "missing leaseTime and no lifetime argument falls back to the 1h default",
			fields: map[string]string{"ipv6": "2001:db8::5"},
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				addr := requireIAAddr(t, resp)
				assert.Equal(t, time.Hour, addr.PreferredLifetime)
				assert.Equal(t, time.Hour, addr.ValidLifetime)
			},
		},
		{
			name:   "a CIDR ipv6 value drops the prefix length",
			fields: map[string]string{"ipv6": "2001:db8::5/64"},
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				addr := requireIAAddr(t, resp)
				assert.Equal(t, "2001:db8::5", addr.IPv6Addr.String())
			},
		},
		{
			name:       "dns is added when requested and an ipv6 entry exists",
			fields:     map[string]string{"ipv6": "2001:db8::5", "dns": "10.0.0.2,2001:db8::53"},
			requestDNS: true,
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				dnsOpt := resp.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer)
				require.NotNil(t, dnsOpt)
				assert.Contains(t, dnsOpt.String(), "2001:db8::53")
			},
		},
		{
			name:       "dns is omitted when it was not requested",
			fields:     map[string]string{"ipv6": "2001:db8::5", "dns": "2001:db8::53"},
			requestDNS: false,
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				assert.Nil(t, resp.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
			},
		},
		{
			name:       "dns is omitted when the field has no ipv6 entry",
			fields:     map[string]string{"ipv6": "2001:db8::5", "dns": "10.0.0.2"},
			requestDNS: true,
			check: func(t *testing.T, resp dhcpv6.DHCPv6) {
				t.Helper()
				assert.Nil(t, resp.GetOneOption(dhcpv6.OptionDNSRecursiveNameServer))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRedis(t)
			f.setHash(macKey(testMAC), tc.fields)
			h6, err := redis.Plugin.Setup6(append([]string{f.addr}, tc.setupArgs...)...)
			require.NoError(t, err)

			duid := &dhcpv6.DUIDLL{HWType: dhcpiana.HWTypeEthernet, LinkLayerAddr: testMAC}
			modifiers := []dhcpv6.Modifier{dhcpv6.WithClientID(duid), dhcpv6.WithIANA()}
			if tc.requestDNS {
				modifiers = append(modifiers, dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer))
			}
			req, resp := v6Request(t, modifiers...)
			gotResp, stop := h6(req, resp)
			require.Same(t, resp, gotResp)
			require.False(t, stop)
			tc.check(t, gotResp)
		})
	}
}
