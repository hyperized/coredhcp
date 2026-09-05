// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// These tests use nothing but the plugin's public surface: the Plugin value,
// the setup functions hanging off it, and the bytes that come out of a
// socket. The TSIG check below is written out again from RFC 8945 rather than
// borrowed from the package, so a mistake made in both places has to be made
// twice.

package ddns_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/ddns"
)

const (
	keyName   = "ddns-key"
	keySecret = "Y29yZWRoY3AtZGRucy1nb2xkZW4tdGVzdC1rZXkhISE="
)

var clientMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// recorder is a socket that keeps what it is sent and never answers. The
// plugin gives up after its retries, which is enough: what these tests are
// after is the datagram, not the reply.
type recorder struct {
	conn net.PacketConn
	got  chan []byte
	seen map[uint16]bool
}

// startRecorder listens on a loopback port until the test ends.
func startRecorder(t *testing.T) *recorder {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &recorder{conn: conn, got: make(chan []byte, 8), seen: map[uint16]bool{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			select {
			case r.got <- msg:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		assert.NoError(t, conn.Close())
		<-done
	})
	return r
}

// addr is the address to configure the plugin with.
func (r *recorder) addr() string { return r.conn.LocalAddr().String() }

// next waits for one message. Nothing here ever answers, so the plugin sends
// each message twice before giving up; a retry carries the ID of the try
// before it, which is how the second copy is recognised and skipped.
func (r *recorder) next(t *testing.T) []byte {
	t.Helper()
	for {
		select {
		case msg := <-r.got:
			id := binary.BigEndian.Uint16(msg[:2])
			if r.seen[id] {
				continue
			}
			r.seen[id] = true
			return msg
		case <-time.After(5 * time.Second):
			t.Fatal("nothing reached the name server")
			return nil
		}
	}
}

// args is a working configuration pointed at r.
func args(r *recorder, extra ...string) []string {
	return append([]string{
		"server:" + r.addr(),
		"zone:home.lan",
		"key:" + keyName + ":" + keySecret,
		"timeout:150ms",
	}, extra...)
}

// update is an RFC 2136 message taken apart far enough to assert on.
type update struct {
	id         uint16
	opCode     int
	zone       string
	records    []record
	tsigName   string
	tsigAlgo   string
	timeSigned uint64
	mac        []byte
	unsigned   []byte // the message as it was digested
}

// record is one entry of the update section.
type record struct {
	name  string
	rtype dnsmessage.Type
	class dnsmessage.Class
	ttl   uint32
	data  []byte
}

// parseUpdate reads a signed update off the wire, following RFC 2136 for the
// sections and RFC 8945 section 4.2 for the TSIG.
func parseUpdate(t *testing.T, msg []byte) update {
	t.Helper()
	var parser dnsmessage.Parser
	hdr, err := parser.Start(msg)
	require.NoError(t, err)

	u := update{id: hdr.ID, opCode: int(hdr.OpCode)}
	q, err := parser.Question()
	require.NoError(t, err)
	u.zone = q.Name.String()
	assert.Equal(t, dnsmessage.TypeSOA, q.Type, "the zone section asks as an SOA")
	require.NoError(t, parser.SkipAllQuestions())

	answers, err := parser.AllAnswers()
	require.NoError(t, err)
	assert.Empty(t, answers, "this plugin sends no prerequisites")

	for {
		rh, err := parser.AuthorityHeader()
		if err != nil {
			break
		}
		body, err := parser.UnknownResource()
		require.NoError(t, err)
		u.records = append(u.records, record{
			name: rh.Name.String(), rtype: rh.Type, class: rh.Class, ttl: rh.TTL, data: body.Data,
		})
	}

	// The TSIG is the last record of the additional section, and its owner
	// name is not compressed, so everything in front of it is what was
	// digested once ARCOUNT is put back.
	require.NoError(t, parser.SkipAllAuthorities())
	ah, err := parser.AdditionalHeader()
	require.NoError(t, err)
	require.Equal(t, dnsmessage.Type(250), ah.Type, "the last record has to be a TSIG")
	require.Equal(t, dnsmessage.ClassANY, ah.Class)
	require.Zero(t, ah.TTL)
	body, err := parser.UnknownResource()
	require.NoError(t, err)

	u.tsigName = ah.Name.String()
	algoLen := int(body.Data[0])
	u.tsigAlgo = string(body.Data[1:1+algoLen]) + "."
	rest := body.Data[algoLen+2:]
	u.timeSigned = uint64(binary.BigEndian.Uint32(rest[2:6])) | uint64(binary.BigEndian.Uint16(rest[:2]))<<32
	macLen := int(binary.BigEndian.Uint16(rest[8:10]))
	u.mac = rest[10 : 10+macLen]

	off := len(msg) - len(body.Data) - 10 - (len(u.tsigName) + 1)
	u.unsigned = append([]byte(nil), msg[:off]...)
	binary.BigEndian.PutUint16(u.unsigned[10:12], binary.BigEndian.Uint16(u.unsigned[10:12])-1)
	return u
}

// checkTSIG recomputes the MAC the way RFC 8945 section 4.3.3 describes it:
// the message without the TSIG record, then the TSIG variables.
func checkTSIG(t *testing.T, u update) {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(keySecret)
	require.NoError(t, err)

	wire := func(name string) []byte {
		var out []byte
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
		return append(out, 0)
	}
	vars := wire(u.tsigName)
	vars = binary.BigEndian.AppendUint16(vars, 255) // CLASS ANY
	vars = binary.BigEndian.AppendUint32(vars, 0)   // TTL
	vars = append(vars, wire(u.tsigAlgo)...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], u.timeSigned)
	vars = append(vars, ts[2:]...)
	vars = binary.BigEndian.AppendUint16(vars, 300) // fudge
	vars = binary.BigEndian.AppendUint16(vars, 0)   // error
	vars = binary.BigEndian.AppendUint16(vars, 0)   // other len

	h := hmac.New(sha256.New, secret)
	h.Write(u.unsigned)
	h.Write(vars)
	assert.True(t, hmac.Equal(h.Sum(nil), u.mac), "the MAC on the wire does not verify")
}

func TestPluginIsRegisterable(t *testing.T) {
	assert.Equal(t, "ddns", ddns.Plugin.Name)
	require.NotNil(t, ddns.Plugin.Setup4)
	require.NotNil(t, ddns.Plugin.Setup6)
	assert.Nil(t, ddns.Plugin.Setup4Ctx, "this plugin reads the packet, not where it came from")
	assert.Nil(t, ddns.Plugin.Setup6Ctx)
	assert.NoError(t, plugins.RegisterPlugin(&ddns.Plugin))
}

func TestSetupRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing at all", nil, "server:<ip> is required"},
		{"a server that has to be resolved first", []string{"server:ns.example.com", "zone:home.lan"}, "IP address"},
		{"no key", []string{"server:10.0.0.53", "zone:home.lan"}, "key:<name>:<secret> is required"},
		{"an unknown argument", []string{"server:10.0.0.53", "zone:home.lan", "key:k:" + keySecret, "ttls:60"}, "unknown argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := ddns.Plugin.Setup4(tc.args...)
			assert.Nil(t, h4)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)

			h6, err := ddns.Plugin.Setup6(tc.args...)
			assert.Nil(t, h6)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestSetupRefusesASecretThatIsNotThere(t *testing.T) {
	_, err := ddns.Plugin.Setup4("server:10.0.0.53", "zone:home.lan", "key:k:env:DDNS_UNSET_IN_THIS_TEST")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unset or empty")
	assert.NotContains(t, err.Error(), keySecret, "no error may carry key material")
}

func TestHandler4WritesASignedUpdate(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup4(args(r, "reverse:10.0.0.0/24", "ttl:60")...)
	require.NoError(t, err)

	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(clientMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptHostName("Laptop")),
	)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.YourIPAddr = net.IP{10, 0, 0, 5}

	got, stop := h(req, resp)
	assert.Same(t, resp, got, "the response is handed on untouched")
	assert.False(t, stop, "the chain carries on")

	forward := parseUpdate(t, r.next(t))
	assert.Equal(t, 5, forward.opCode, "opcode 5 is UPDATE")
	assert.Equal(t, "home.lan.", forward.zone)
	assert.Equal(t, "ddns-key.", forward.tsigName)
	assert.Equal(t, "hmac-sha256.", forward.tsigAlgo)
	checkTSIG(t, forward)

	require.Len(t, forward.records, 2)
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: dnsmessage.TypeA, class: dnsmessage.ClassANY, data: []byte{},
	}, forward.records[0], "an RRset delete carries no data and no TTL")
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: dnsmessage.TypeA, class: dnsmessage.ClassINET,
		ttl: 60, data: []byte{10, 0, 0, 5},
	}, forward.records[1])

	reverse := parseUpdate(t, r.next(t))
	assert.Equal(t, "0.0.10.in-addr.arpa.", reverse.zone)
	checkTSIG(t, reverse)
	require.Len(t, reverse.records, 2)
	assert.Equal(t, "5.0.0.10.in-addr.arpa.", reverse.records[0].name)
	assert.Equal(t, dnsmessage.TypePTR, reverse.records[1].rtype)
}

func TestHandler4ReleaseOnlyDeletes(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup4(args(r)...)
	require.NoError(t, err)

	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(clientMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		dhcpv4.WithOption(dhcpv4.OptHostName("laptop")),
	)
	require.NoError(t, err)
	req.ClientIPAddr = net.IP{10, 0, 0, 5}
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)

	_, stop := h(req, resp)
	assert.False(t, stop)

	got := parseUpdate(t, r.next(t))
	checkTSIG(t, got)
	require.Len(t, got.records, 1, "a withdrawal is the delete on its own")
	assert.Equal(t, dnsmessage.ClassANY, got.records[0].class)
}

func TestHandler6WritesASignedUpdate(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup6(args(r, "reverse:2001:db8::/32")...)
	require.NoError(t, err)

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.AddOption(&dhcpv6.OptFQDN{DomainName: &rfc1035label.Labels{Labels: []string{"laptop"}}})

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	var ia dhcpv6.IdentityOptions
	ia.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2001:db8::1"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     time.Hour,
	})
	resp.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}, Options: ia})

	got, stop := h(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)

	forward := parseUpdate(t, r.next(t))
	checkTSIG(t, forward)
	require.Len(t, forward.records, 2)
	assert.Equal(t, dnsmessage.TypeAAAA, forward.records[0].rtype)
	assert.Equal(t, net.ParseIP("2001:db8::1").To16(), net.IP(forward.records[1].data))

	reverse := parseUpdate(t, r.next(t))
	assert.Equal(t, "8.b.d.0.1.0.0.2.ip6.arpa.", reverse.zone)
	checkTSIG(t, reverse)
}

func TestHandlersNeverStopTheChain(t *testing.T) {
	r := startRecorder(t)
	h4, err := ddns.Plugin.Setup4(args(r)...)
	require.NoError(t, err)

	for _, mtype := range []dhcpv4.MessageType{
		dhcpv4.MessageTypeDiscover,
		dhcpv4.MessageTypeRequest,
		dhcpv4.MessageTypeRelease,
		dhcpv4.MessageTypeDecline,
		dhcpv4.MessageTypeInform,
	} {
		t.Run(mtype.String(), func(t *testing.T) {
			req, err := dhcpv4.New(dhcpv4.WithHwAddr(clientMAC), dhcpv4.WithMessageType(mtype))
			require.NoError(t, err)
			resp, err := dhcpv4.NewReplyFromRequest(req)
			require.NoError(t, err)
			got, stop := h4(req, resp)
			assert.Same(t, resp, got)
			assert.False(t, stop)
		})
	}

	h6, err := ddns.Plugin.Setup6(args(r)...)
	require.NoError(t, err)
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	got, stop := h6(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)
}
