// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// These tests use nothing but the plugin's public surface: the Plugin value,
// the setup functions hanging off it, and the bytes that come out of a
// socket. The TSIG check below is written out again from RFC 8945 rather than
// borrowed from the package, so a mistake made in both places has to be made
// twice. The same goes for the DHCID, which is rebuilt here from RFC 4701.

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
	"github.com/insomniacslk/dhcp/iana"
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

	// Written out rather than imported: these tests check the package
	// against the RFCs, not against itself.
	typeTSIG  = dnsmessage.Type(250)
	typeDHCID = dnsmessage.Type(49)

	headerLen  = 12
	arcountOff = 10

	// The plugin never checks the time on an answer beyond letting the MAC
	// cover it, so any fixed timestamp works here.
	signedAt = 1788589641

	// updateResponseFlags is QR set with opcode 5 and RCODE 0.
	updateResponseFlags = 0xa800
)

var clientMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// Decoding a constant of this file cannot fail; a panic in a test binary is
// a clearer failure than a silently empty key.
var secret = mustDecode(keySecret)

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// recorder is a name server that answers every request with a signed
// NOERROR.
//
// Answering matters now: the plugin only writes a PTR once the forward zone
// has taken the address, and it only remembers holding a name once the
// server has said so, so a server that stays silent leaves half these tests
// with nothing to look at.
type recorder struct {
	conn net.PacketConn
	got  chan []byte
}

// startRecorder listens on a loopback port until the test ends.
func startRecorder(t *testing.T) *recorder {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &recorder{conn: conn, got: make(chan []byte, 8)}
	done := make(chan struct{})
	go r.serve(done)
	t.Cleanup(func() {
		assert.NoError(t, conn.Close())
		<-done
	})
	return r
}

func (r *recorder) serve(done chan struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for {
		n, peer, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		select {
		case r.got <- msg:
		default:
		}
		if resp := answerTo(msg); resp != nil {
			_, _ = r.conn.WriteTo(resp, peer)
		}
	}
}

// addr is the address to configure the plugin with.
func (r *recorder) addr() string { return r.conn.LocalAddr().String() }

// next waits for one message.
func (r *recorder) next(t *testing.T) []byte {
	t.Helper()
	select {
	case msg := <-r.got:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the name server")
		return nil
	}
}

// answerTo signs an empty NOERROR the way RFC 8945 section 5.4 has a server
// sign one, with the MAC of the request digested in front of the message.
func answerTo(req []byte) []byte {
	reqMAC, ok := tsigMAC(req)
	if !ok {
		return nil
	}
	resp := make([]byte, 0, headerLen)
	resp = append(resp, req[:2]...) // the same ID
	resp = binary.BigEndian.AppendUint16(resp, updateResponseFlags)
	resp = binary.BigEndian.AppendUint16(resp, 0) // QDCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0) // ANCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0) // NSCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0) // ARCOUNT, set below once the TSIG is appended

	h := hmac.New(sha256.New, secret)
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reqMAC))))
	h.Write(reqMAC)
	h.Write(resp)
	h.Write(tsigVars(keyName+".", "hmac-sha256.", signedAt))

	// The digest is taken, so the record can go on the end now.
	resp = append(resp, wireName(keyName+".")...)
	resp = binary.BigEndian.AppendUint16(resp, uint16(typeTSIG))
	resp = binary.BigEndian.AppendUint16(resp, 255) // CLASS ANY
	resp = binary.BigEndian.AppendUint32(resp, 0)   // TTL
	rdata := tsigRDATA(h.Sum(nil), binary.BigEndian.Uint16(req[:2]))
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
	resp = append(resp, rdata...)
	binary.BigEndian.PutUint16(resp[arcountOff:], 1)
	return resp
}

// tsigRDATA is the RDATA of RFC 8945 section 4.2.
func tsigRDATA(mac []byte, origID uint16) []byte {
	out := wireName("hmac-sha256.")
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], signedAt)
	out = append(out, ts[2:]...)
	out = binary.BigEndian.AppendUint16(out, 300) // fudge
	out = binary.BigEndian.AppendUint16(out, uint16(len(mac)))
	out = append(out, mac...)
	out = binary.BigEndian.AppendUint16(out, origID)
	out = binary.BigEndian.AppendUint16(out, 0) // error
	return binary.BigEndian.AppendUint16(out, 0)
}

func tsigMAC(msg []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, false
	}
	for _, skip := range []func() error{p.SkipAllQuestions, p.SkipAllAnswers, p.SkipAllAuthorities} {
		if err := skip(); err != nil {
			return nil, false
		}
	}
	var rdata []byte
	for {
		hdr, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		body, err := p.UnknownResource()
		if err != nil {
			return nil, false
		}
		if hdr.Type == typeTSIG {
			rdata = body.Data
		}
	}
	return macOf(rdata)
}

// macOf picks the MAC out of a TSIG RDATA: a one label algorithm name, six
// octets of time, two of fudge, then the length and the MAC itself.
func macOf(rdata []byte) ([]byte, bool) {
	if len(rdata) == 0 {
		return nil, false
	}
	rest := rdata[int(rdata[0])+2:]
	if len(rest) < 10 {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(rest[8:10]))
	if len(rest) < 10+length {
		return nil, false
	}
	return rest[10 : 10+length], true
}

// wireName is a fully qualified name in uncompressed wire form.
func wireName(name string) []byte {
	var out []byte
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// tsigVars is the run of TSIG variables that follows the message in the
// digest, per RFC 8945 section 4.3.3.
func tsigVars(name, algo string, timeSigned uint64) []byte {
	out := wireName(name)
	out = binary.BigEndian.AppendUint16(out, 255) // CLASS ANY
	out = binary.BigEndian.AppendUint32(out, 0)   // TTL
	out = append(out, wireName(algo)...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timeSigned)
	out = append(out, ts[2:]...)
	out = binary.BigEndian.AppendUint16(out, 300) // fudge
	out = binary.BigEndian.AppendUint16(out, 0)   // error
	return binary.BigEndian.AppendUint16(out, 0)  // other len
}

// dhcid is the record RFC 4701 section 3.5 describes, built here from the
// RFC rather than from the package under test: the identifier type, the
// digest type, and SHA-256 over the identifier and the name in wire form.
func dhcid(code uint16, identifier []byte, fqdn string) []byte {
	sum := sha256.Sum256(append(append([]byte{}, identifier...), wireName(fqdn)...))
	out := binary.BigEndian.AppendUint16(nil, code)
	out = append(out, 1) // digest type SHA-256
	return append(out, sum[:]...)
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
	prereqs    []record
	records    []record
	tsigName   string
	tsigAlgo   string
	timeSigned uint64
	mac        []byte
	unsigned   []byte // the message as it was digested
}

// record is one entry of the prerequisite or update section.
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

	// The answer section of an update holds the prerequisites.
	for {
		rh, hdrErr := parser.AnswerHeader()
		if hdrErr != nil {
			break
		}
		body, bodyErr := parser.UnknownResource()
		require.NoError(t, bodyErr)
		u.prereqs = append(u.prereqs, record{
			name: rh.Name.String(), rtype: rh.Type, class: rh.Class, ttl: rh.TTL, data: body.Data,
		})
	}
	require.NoError(t, parser.SkipAllAnswers())

	for {
		rh, hdrErr := parser.AuthorityHeader()
		if hdrErr != nil {
			break
		}
		body, bodyErr := parser.UnknownResource()
		require.NoError(t, bodyErr)
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
	require.Equal(t, typeTSIG, ah.Type, "the last record has to be a TSIG")
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
	binary.BigEndian.PutUint16(u.unsigned[arcountOff:headerLen], binary.BigEndian.Uint16(u.unsigned[arcountOff:headerLen])-1)
	return u
}

// checkTSIG recomputes the MAC the way RFC 8945 section 4.3.3 describes it:
// the message without the TSIG record, then the TSIG variables.
func checkTSIG(t *testing.T, u update) {
	t.Helper()
	h := hmac.New(sha256.New, secret)
	h.Write(u.unsigned)
	h.Write(tsigVars(u.tsigName, u.tsigAlgo, u.timeSigned))
	assert.True(t, hmac.Equal(h.Sum(nil), u.mac), "the MAC on the wire does not verify")
}

func TestPluginIsRegisterable(t *testing.T) {
	assert.Equal(t, "ddns", ddns.Plugin.Name)
	require.NotNil(t, ddns.Plugin.Setup4)
	require.NotNil(t, ddns.Plugin.Setup6)
	assert.Nil(t, ddns.Plugin.Setup4Ctx, "this plugin reads the packet, not where it came from")
	assert.Nil(t, ddns.Plugin.Setup6Ctx)
	// The registry is a package global and a second registration under the
	// same name panics, so put the entry back the way it was found. Without
	// this, `go test -count=2` takes the whole binary down on the second run.
	t.Cleanup(func() { delete(plugins.RegisteredPlugins, ddns.Plugin.Name) })
	require.NoError(t, plugins.RegisterPlugin(&ddns.Plugin))
}

func TestSetupRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing at all", nil, "server:<ip> is missing"},
		{"a server that has to be resolved first", []string{"server:ns.example.com", "zone:home.lan"}, "IP address"},
		{"no key", []string{"server:10.0.0.53", "zone:home.lan"}, "key:<name>:<secret> is missing"},
		{"an unknown argument", []string{"server:10.0.0.53", "zone:home.lan", "key:k:" + keySecret, "ttls:60"}, `argument "ttls:60" is not one this plugin takes`},
		{
			"a protected name in another zone",
			[]string{"server:10.0.0.53", "zone:home.lan", "key:k:" + keySecret, "protect:vpn.example.com"},
			"protect:vpn.example.com is not a name this plugin can protect",
		},
		{
			"a protect: argument with nothing in it",
			[]string{"server:10.0.0.53", "zone:home.lan", "key:k:" + keySecret, "protect:vpn,"},
			"protect:vpn, holds an empty name",
		},
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

// ack4 stands in for the ACK a previous plugin in the chain would have built.
func ack4(t *testing.T, host string, addr net.IP) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(clientMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptHostName(host)),
	)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.YourIPAddr = addr
	return req, resp
}

func TestHandler4WritesASignedUpdate(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup4(args(r, "reverse:10.0.0.0/24", "ttl:60")...)
	require.NoError(t, err)

	req, resp := ack4(t, "Laptop", net.IP{10, 0, 0, 5})
	got, stop := h(req, resp)
	assert.Same(t, resp, got, "the response is handed on untouched")
	assert.False(t, stop, "the chain carries on")

	forward := parseUpdate(t, r.next(t))
	assert.Equal(t, 5, forward.opCode, "opcode 5 is UPDATE")
	assert.Equal(t, "home.lan.", forward.zone)
	assert.Equal(t, "ddns-key.", forward.tsigName)
	assert.Equal(t, "hmac-sha256.", forward.tsigAlgo)
	checkTSIG(t, forward)

	// RFC 4703 section 5.3.1: the first attempt at a name asks that no
	// DHCID be there, which is what keeps it from taking someone else's.
	require.Len(t, forward.prereqs, 1)
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: typeDHCID, class: dnsmessage.Class(254), data: []byte{},
	}, forward.prereqs[0])

	want := dhcid(0, append([]byte{byte(iana.HWTypeEthernet)}, clientMAC...), "laptop.home.lan.")
	require.Len(t, forward.records, 3)
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: dnsmessage.TypeA, class: dnsmessage.ClassANY, data: []byte{},
	}, forward.records[0], "an RRset delete carries no data and no TTL")
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: dnsmessage.TypeA, class: dnsmessage.ClassINET,
		ttl: 60, data: []byte{10, 0, 0, 5},
	}, forward.records[1])
	assert.Equal(t, record{
		name: "laptop.home.lan.", rtype: typeDHCID, class: dnsmessage.ClassINET, ttl: 60, data: want,
	}, forward.records[2], "the DHCID names the client the address was handed to")

	reverse := parseUpdate(t, r.next(t))
	assert.Equal(t, "0.0.10.in-addr.arpa.", reverse.zone)
	assert.Empty(t, reverse.prereqs, "a reverse name is the server's own, so nothing has to be checked")
	checkTSIG(t, reverse)
	require.Len(t, reverse.records, 2)
	assert.Equal(t, "5.0.0.10.in-addr.arpa.", reverse.records[0].name)
	assert.Equal(t, dnsmessage.TypePTR, reverse.records[1].rtype)
}

func TestHandler4ReleaseWithdrawsWhatItWasGiven(t *testing.T) {
	r := startRecorder(t)
	// The reverse zone is configured so the lease produces a second
	// message: that one is only sent once the forward update came back
	// accepted, which is also when the name is remembered. Waiting for it
	// is how this test knows the release has something to weigh.
	h, err := ddns.Plugin.Setup4(args(r, "reverse:10.0.0.0/24")...)
	require.NoError(t, err)

	req, resp := ack4(t, "laptop", net.IP{10, 0, 0, 5})
	h(req, resp)
	r.next(t)
	r.next(t)

	rel, err := dhcpv4.New(
		dhcpv4.WithHwAddr(clientMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		dhcpv4.WithOption(dhcpv4.OptHostName("laptop")),
	)
	require.NoError(t, err)
	rel.ClientIPAddr = net.IP{10, 0, 0, 5}
	relResp, err := dhcpv4.NewReplyFromRequest(rel)
	require.NoError(t, err)

	_, stop := h(rel, relResp)
	assert.False(t, stop)

	got := parseUpdate(t, r.next(t))
	checkTSIG(t, got)
	require.Len(t, got.prereqs, 1)
	assert.Equal(t, typeDHCID, got.prereqs[0].rtype)
	assert.Equal(t, dnsmessage.ClassINET, got.prereqs[0].class,
		"a delete goes out under the prerequisite that the DHCID is still ours")

	require.Len(t, got.records, 2, "the addresses and the DHCID that held them")
	assert.Equal(t, dnsmessage.ClassANY, got.records[0].class)
	assert.Equal(t, typeDHCID, got.records[1].rtype)
	assert.Equal(t, dnsmessage.Class(254), got.records[1].class, "one record, not the whole RRset")
}

func TestHandler4IgnoresAReleaseItNeverWrote(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup4(args(r)...)
	require.NoError(t, err)

	rel, err := dhcpv4.New(
		dhcpv4.WithHwAddr(clientMAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		dhcpv4.WithOption(dhcpv4.OptHostName("vpn")),
	)
	require.NoError(t, err)
	rel.ClientIPAddr = net.IP{10, 0, 0, 5}
	resp, err := dhcpv4.NewReplyFromRequest(rel)
	require.NoError(t, err)

	_, stop := h(rel, resp)
	assert.False(t, stop)

	select {
	case msg := <-r.got:
		t.Fatalf("a release for a name this server never wrote reached the wire: %x", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandler4LeavesProtectedNamesAlone(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup4(args(r, "protect:vpn,gateway")...)
	require.NoError(t, err)

	req, resp := ack4(t, "vpn", net.IP{10, 0, 0, 5})
	h(req, resp)

	select {
	case msg := <-r.got:
		t.Fatalf("a protected name was written: %x", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandler6WritesASignedUpdate(t *testing.T) {
	r := startRecorder(t)
	h, err := ddns.Plugin.Setup6(args(r, "reverse:2001:db8::/32")...)
	require.NoError(t, err)

	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: clientMAC}
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
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
	require.Len(t, forward.records, 3)
	assert.Equal(t, dnsmessage.TypeAAAA, forward.records[0].rtype)
	assert.Equal(t, net.ParseIP("2001:db8::1").To16(), net.IP(forward.records[1].data))

	// Over DHCPv6 the identifier of RFC 4701 is the client's DUID, under
	// type code 2.
	assert.Equal(t, dhcid(2, duid.ToBytes(), "laptop.home.lan."), forward.records[2].data)

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
			req, reqErr := dhcpv4.New(dhcpv4.WithHwAddr(clientMAC), dhcpv4.WithMessageType(mtype))
			require.NoError(t, reqErr)
			resp, respErr := dhcpv4.NewReplyFromRequest(req)
			require.NoError(t, respErr)
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
