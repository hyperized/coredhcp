// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// The key every test signs with; it's the one in testdata, so the golden
// capture and the tests that build messages from scratch use the same material.
const (
	testKeyName   = "ddns-key"
	testKeySecret = "Y29yZWRoY3AtZGRucy1nb2xkZW4tdGVzdC1rZXkhISE="
	testZone      = "home.lan."
)

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// Written out by hand, so the expectations below don't lean on the packer
// they are there to check.
const (
	wireHomeLan     = "04686f6d65036c616e00"           // home.lan.
	wireHostHomeLan = "04686f737404686f6d65036c616e00" // host.home.lan.
	// 0.0.10.in-addr.arpa. and 5.0.0.10.in-addr.arpa.
	wireRevZone24 = "0130" + "0130" + "023130" + "07696e2d61646472" + "0461727061" + "00"
	wireRevPTR    = "0135" + "0130" + "0130" + "023130" + "07696e2d61646472" + "0461727061" + "00"
)

func newTestKey(t *testing.T) tsigKey {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(testKeySecret)
	require.NoError(t, err)
	k, err := newTSIGKey(testKeyName, "hmac-sha256", secret)
	require.NoError(t, err)
	return k
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err)
	return b
}

// Only as real as these tests need: records every request and answers with
// what the test asked for.
type fakeDNS struct {
	conn net.PacketConn
	key  tsigKey

	mu       sync.Mutex
	requests [][]byte

	// Knobs, all read under mu. ignore drops the first n requests without
	// answering, staging a lost datagram.
	ignore    int
	rcode     dnsmessage.RCode
	truncated bool
	idOffset  uint16
	corruptAt int // index into the response to flip a bit in, -1 for none
	unsigned  bool
	signedAt  time.Time
}

func startFakeDNS(t *testing.T, key tsigKey) *fakeDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeDNS{conn: conn, key: key, corruptAt: -1, signedAt: time.Unix(1788589641, 0)}
	done := make(chan struct{})
	go f.serve(done)
	t.Cleanup(func() {
		assert.NoError(t, conn.Close())
		<-done
	})
	return f
}

func (f *fakeDNS) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeDNS) serve(done chan struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for {
		n, peer, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		if resp := f.answer(req); resp != nil {
			_, _ = f.conn.WriteTo(resp, peer)
		}
	}
}

func (f *fakeDNS) answer(req []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.ignore > 0 {
		f.ignore--
		return nil
	}
	rec, err := findTSIG(req)
	if err != nil {
		return nil
	}
	id := binary.BigEndian.Uint16(req[:2]) + f.idOffset
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, OpCode: opCodeUpdate, RCode: f.rcode, Truncated: f.truncated,
	})
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	if f.unsigned {
		return msg
	}
	resp := f.sign(msg, rec.mac, id)
	if f.corruptAt >= 0 {
		resp[len(resp)-1-f.corruptAt] ^= 0xff
	}
	return resp
}

// RFC 8945 section 5.4: the request's MAC is digested in front of the response.
func (f *fakeDNS) sign(msg, requestMAC []byte, id uint16) []byte {
	ts := unixSeconds(f.signedAt)
	mac := f.key.digest(msg, ts, requestMAC)
	out := f.key.appendRR(msg, ts, mac, id)
	binary.BigEndian.PutUint16(out[arcountOff:], binary.BigEndian.Uint16(out[arcountOff:])+1)
	return out
}

func (f *fakeDNS) received() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.requests))
	copy(out, f.requests)
	return out
}

func (f *fakeDNS) set(apply func(*fakeDNS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

// Does not start the worker.
func newTestPlugin(t *testing.T, f *fakeDNS, extra ...string) *pluginState {
	t.Helper()
	args := append([]string{
		"server:" + f.addr(),
		"zone:home.lan",
		"key:" + testKeyName + ":" + testKeySecret,
	}, extra...)
	p, err := newPluginState(args...)
	require.NoError(t, err)
	return p
}

// Runs the worker for exactly one job, so a test can assert on what reached
// the server without racing the goroutine.
func (p *pluginState) drainOne(t *testing.T) {
	t.Helper()
	select {
	case j := <-p.queue:
		p.apply(j)
	default:
		t.Fatal("nothing was queued")
	}
}

func TestHostFQDN(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        error
	}{
		{name: "single label", in: "laptop", want: "laptop.home.lan."},
		{name: "uppercase", in: "LAPTOP", want: "laptop.home.lan."},
		{name: "surrounding space", in: "  laptop\t", want: "laptop.home.lan."},
		{name: "fully qualified", in: "laptop.home.lan", want: "laptop.home.lan."},
		{name: "fully qualified with a dot", in: "laptop.home.lan.", want: "laptop.home.lan."},
		{name: "subdomain of the zone", in: "a.b.home.lan", want: "a.b.home.lan."},
		{name: "digits and hyphens", in: "esp32-01", want: "esp32-01.home.lan."},
		{name: "empty", in: "", wantErr: ErrNoHostname},
		{name: "only a dot", in: ".", wantErr: ErrNoHostname},
		{name: "only spaces", in: "   ", wantErr: ErrNoHostname},
		{name: "another zone", in: "laptop.example.com", wantErr: ErrOutsideZone},
		{name: "the zone apex", in: "home.lan", wantErr: ErrOutsideZone},
		{name: "a zone that merely ends the same", in: "evilhome.lan", wantErr: ErrOutsideZone},
		{name: "underscore", in: "lap_top", wantErr: ErrInvalidHostname},
		{name: "leading hyphen", in: "-laptop", wantErr: ErrInvalidHostname},
		{name: "trailing hyphen", in: "laptop-", wantErr: ErrInvalidHostname},
		{name: "empty label", in: "a..b.home.lan", wantErr: ErrInvalidHostname},
		{name: "label too long", in: strings.Repeat("a", 64), wantErr: ErrInvalidHostname},
		{name: "name too long", in: strings.Repeat("a.", 130) + "home.lan", wantErr: ErrInvalidHostname},
		{name: "not ASCII", in: "café", wantErr: ErrInvalidHostname},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostFQDN(tc.in, testZone)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCanonicalZone(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"bare", "home.lan", "home.lan."},
		{"trailing dot", "home.lan.", "home.lan."},
		{"uppercase", "Home.LAN", "home.lan."},
		{"single label", "lan", "lan."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalZone(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"only a dot", "."},
		{"bad character", "home_lan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := canonicalZone(tc.in)
			assert.ErrorIs(t, err, ErrInvalidHostname)
		})
	}
}

func TestReverseZone(t *testing.T) {
	for _, tc := range []struct{ name, cidr, want string }{
		{"IPv4 slash 8", "10.0.0.0/8", "10.in-addr.arpa."},
		{"IPv4 slash 16", "10.1.0.0/16", "1.10.in-addr.arpa."},
		{"IPv4 slash 24", "10.0.0.0/24", "0.0.10.in-addr.arpa."},
		{"IPv4 slash 32", "10.0.0.5/32", "5.0.0.10.in-addr.arpa."},
		{"IPv4 slash 0", "0.0.0.0/0", "in-addr.arpa."},
		{"IPv6 slash 48", "2001:db8:1::/48", "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"IPv6 slash 64", "2001:db8::/64", "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"IPv6 slash 32", "2001:db8::/32", "8.b.d.0.1.0.0.2.ip6.arpa."},
		{"IPv6 slash 0", "::/0", "ip6.arpa."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pfx := netip.MustParsePrefix(tc.cidr)
			got, err := reverseZone(pfx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	for _, tc := range []struct{ name, cidr string }{
		{"IPv4 off an octet", "10.0.0.0/25"},
		{"IPv6 off a nibble", "2001:db8::/33"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reverseZone(netip.MustParsePrefix(tc.cidr))
			assert.ErrorIs(t, err, ErrReverseBoundary)
		})
	}
}

func TestPTRName(t *testing.T) {
	assert.Equal(t, "5.0.0.10.in-addr.arpa.", ptrName(netip.MustParseAddr("10.0.0.5")))
	assert.Equal(t,
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		ptrName(netip.MustParseAddr("2001:db8::1")))
}

func TestPackName(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"root", ".", "00"},
		{"one label", "lan.", "036c616e00"},
		{"two labels", "home.lan.", wireHomeLan},
		{"uppercase is folded", "HOME.LAN.", wireHomeLan},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := packName(tc.in)
			require.NoError(t, err)
			assert.Equal(t, fromHex(t, tc.want), got)
		})
	}
	for _, tc := range []struct{ name, in string }{
		{"no trailing dot", "home.lan"},
		{"empty label", "home..lan."},
		{"label too long", strings.Repeat("a", 64) + "."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := packName(tc.in)
			assert.ErrorIs(t, err, ErrBadName)
		})
	}
}

func TestReadName(t *testing.T) {
	t.Run("two labels", func(t *testing.T) {
		name, n, err := readName(append(fromHex(t, wireHomeLan), 0xff))
		require.NoError(t, err)
		assert.Equal(t, "home.lan.", name)
		assert.Equal(t, 10, n)
	})
	t.Run("root", func(t *testing.T) {
		name, n, err := readName([]byte{0})
		require.NoError(t, err)
		assert.Equal(t, ".", name)
		assert.Equal(t, 1, n)
	})
	t.Run("uppercase is folded", func(t *testing.T) {
		name, _, err := readName([]byte{4, 'H', 'O', 'S', 'T', 0})
		require.NoError(t, err)
		assert.Equal(t, "host.", name)
	})
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"compression pointer", []byte{0xc0, 0x0c}},
		{"label runs past the end", []byte{4, 'h', 'o'}},
		{"not terminated", []byte{1, 'a'}},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := readName(tc.in)
			assert.ErrorIs(t, err, ErrBadName)
		})
	}
}

// The check that matters: the MAC this package computes has to match the MAC
// ISC's nsupdate computed for the same message, key and time.
func TestTSIGAgainstNsupdate(t *testing.T) {
	msg, err := os.ReadFile("testdata/nsupdate-add-a.bin")
	require.NoError(t, err)
	key := newTestKey(t)

	rec, err := findTSIG(msg)
	require.NoError(t, err)
	assert.Equal(t, "ddns-key.", rec.name)
	assert.Equal(t, "hmac-sha256.", rec.algo)
	assert.Equal(t, uint64(1788589641), rec.timeSigned)
	assert.Equal(t, uint16(tsigFudge), rec.fudge)
	assert.Equal(t, uint16(0xe06e), rec.origID)
	assert.Zero(t, rec.rcode)
	assert.Empty(t, rec.other)
	assert.Equal(t,
		fromHex(t, "e3500ee31020867d470b67d236f7151f94ee8c0b78df905892de2905378c5cc2"),
		rec.mac)

	unsigned, err := key.stripTSIG(msg, rec.rdataLen)
	require.NoError(t, err)
	assert.Len(t, unsigned, 47, "the TSIG record starts at offset 47")
	assert.Zero(t, binary.BigEndian.Uint16(unsigned[arcountOff:]), "ARCOUNT goes back to what it was")

	// A request is digested with no request MAC in front of it.
	assert.Equal(t, rec.mac, key.digest(unsigned, rec.timeSigned, nil))
}

// Same path TestTSIGAgainstNsupdate checks, driven from the other end.
func TestSignRoundTrip(t *testing.T) {
	key := newTestKey(t)
	msg, err := buildUpdate(0x1234, testZone, []change{deleteRRset("host.home.lan.", dnsmessage.TypeA)})
	require.NoError(t, err)
	before := len(msg)

	signed, mac := key.sign(msg, time.Unix(1788589641, 0), 0x1234)
	assert.Len(t, mac, 32)
	assert.Greater(t, len(signed), before)
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(signed[arcountOff:]))

	rec, err := findTSIG(signed)
	require.NoError(t, err)
	assert.Equal(t, mac, rec.mac)
	assert.Equal(t, uint64(1788589641), rec.timeSigned)
	assert.Equal(t, uint16(0x1234), rec.origID)
	assert.NoError(t, key.verify(signed, rec, nil))
}

func TestNewTSIGKey(t *testing.T) {
	secret := []byte("secret")
	t.Run("defaults to a dotted name", func(t *testing.T) {
		k, err := newTSIGKey("ddns-key", "hmac-sha512", secret)
		require.NoError(t, err)
		assert.Equal(t, "ddns-key.", k.name)
		assert.Equal(t, "hmac-sha512.", k.algo)
		assert.Equal(t, fromHex(t, "0864646e732d6b657900"), k.nameWire)
	})
	t.Run("a dotted name is left alone", func(t *testing.T) {
		k, err := newTSIGKey("ddns-key.", "hmac-sha1", secret)
		require.NoError(t, err)
		assert.Equal(t, "ddns-key.", k.name)
	})
	t.Run("unknown algorithm", func(t *testing.T) {
		_, err := newTSIGKey("ddns-key", "hmac-md5", secret)
		assert.ErrorIs(t, err, ErrUnknownAlgorithm)
	})
	t.Run("unusable key name", func(t *testing.T) {
		_, err := newTSIGKey("ddns..key", "hmac-sha256", secret)
		assert.ErrorIs(t, err, ErrBadName)
	})
	t.Run("the algorithm wire form matches the general packer", func(t *testing.T) {
		for name := range algorithms {
			want, err := packName(name + ".")
			require.NoError(t, err)
			assert.Equal(t, want, packLabel(name), name)
		}
	})
}

func TestAlgorithmNames(t *testing.T) {
	assert.Equal(t, []string{"hmac-sha1", "hmac-sha256", "hmac-sha512"}, algorithmNames())
}

func TestUnixSeconds(t *testing.T) {
	assert.Equal(t, uint64(1788589641), unixSeconds(time.Unix(1788589641, 0)))
	assert.Zero(t, unixSeconds(time.Unix(-1, 0)), "a clock that has not been set reads as the epoch")
}

func TestDigestWithRequestMAC(t *testing.T) {
	key := newTestKey(t)
	msg := []byte("message")
	plain := key.digest(msg, 1, nil)
	withMAC := key.digest(msg, 1, []byte("abcd"))
	assert.NotEqual(t, plain, withMAC, "the request MAC has to reach the digest")
	assert.Equal(t, plain, key.digest(msg, 1, []byte{}), "an empty MAC is no MAC")
}

func TestFindTSIGErrors(t *testing.T) {
	key := newTestKey(t)
	t.Run("not a DNS message", func(t *testing.T) {
		_, err := findTSIG([]byte{1, 2, 3})
		assert.Error(t, err)
	})
	t.Run("no additional records", func(t *testing.T) {
		msg, err := buildUpdate(1, testZone, nil)
		require.NoError(t, err)
		_, err = findTSIG(msg)
		assert.ErrorIs(t, err, ErrNoTSIG)
	})
	t.Run("the last record is not a TSIG", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
		require.NoError(t, b.StartAdditionals())
		require.NoError(t, b.AResource(
			dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("host.home.lan."), Class: dnsmessage.ClassINET},
			dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}}))
		msg, err := b.Finish()
		require.NoError(t, err)
		_, err = findTSIG(msg)
		assert.ErrorIs(t, err, ErrNoTSIG)
	})
	t.Run("a record in front of the TSIG is walked past", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
		require.NoError(t, b.StartAdditionals())
		require.NoError(t, b.AResource(
			dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("host.home.lan."), Class: dnsmessage.ClassINET},
			dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}}))
		msg, err := b.Finish()
		require.NoError(t, err)
		signed, _ := key.sign(msg, time.Unix(1, 0), 1)
		rec, err := findTSIG(signed)
		require.NoError(t, err)
		assert.Equal(t, "ddns-key.", rec.name)
	})
	t.Run("truncated sections", func(t *testing.T) {
		msg, err := buildUpdate(1, testZone, []change{deleteRRset("host.home.lan.", dnsmessage.TypeA)})
		require.NoError(t, err)
		_, err = findTSIG(msg[:len(msg)-4])
		assert.Error(t, err)
	})
	for _, tc := range []struct{ name, msg string }{
		// Each header promises one record in a section, then stops, so the
		// walk fails in a different place every time.
		{"a promised question that is not there", "000128000001000000000000"},
		{"a promised answer that is not there", "000128000000000100000000"},
		{"a promised update that is not there", "000128000000000000010000"},
		{"a promised additional that is not there", "000128000000000000000001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := findTSIG(fromHex(t, tc.msg))
			assert.Error(t, err)
		})
	}
	t.Run("a record whose RDATA runs past the end", func(t *testing.T) {
		// ARCOUNT 1, root name, type TSIG, class ANY, TTL 0, RDLENGTH 16 with
		// nothing behind it.
		msg := fromHex(t, "000128000000000000000001"+"00"+"00fa"+"00ff"+"00000000"+"0010")
		_, err := findTSIG(msg)
		assert.Error(t, err)
	})
	t.Run("a TSIG whose RDATA does not parse", func(t *testing.T) {
		msg := fromHex(t, "000128000000000000000001"+"00"+"00fa"+"00ff"+"00000000"+"0002"+"c00c")
		_, err := findTSIG(msg)
		assert.ErrorIs(t, err, ErrBadName)
	})
}

func TestParseTSIGRDATA(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		_, err := parseTSIGRDATA(fromHex(t, "0b686d61632d73686132353600"))
		assert.ErrorIs(t, err, ErrShortRDATA)
	})
	t.Run("bad algorithm name", func(t *testing.T) {
		_, err := parseTSIGRDATA([]byte{0xc0, 0x0c})
		assert.ErrorIs(t, err, ErrBadName)
	})
	t.Run("MAC longer than the rdata", func(t *testing.T) {
		rdata := fromHex(t, "0b686d61632d7368613235360000006a9bb649012c00ff")
		_, err := parseTSIGRDATA(rdata)
		assert.ErrorIs(t, err, ErrShortRDATA)
	})
	t.Run("other data", func(t *testing.T) {
		rdata := fromHex(t,
			"0b686d61632d7368613235360000006a9bb649012c0000"+ // algo, time, fudge, mac size 0
				"e06e"+"0012"+"0006"+"00006a9bb64a") // orig id, BADTIME, other len 6, other
		rec, err := parseTSIGRDATA(rdata)
		require.NoError(t, err)
		assert.Equal(t, uint16(18), rec.rcode)
		assert.Len(t, rec.other, 6)
	})
}

func TestRDATAReader(t *testing.T) {
	t.Run("a negative length is refused", func(t *testing.T) {
		r := rdataReader{b: []byte{1, 2, 3}}
		assert.Nil(t, r.take(-1))
		assert.ErrorIs(t, r.err, ErrShortRDATA)
	})
	t.Run("every read after a failure is a no-op", func(t *testing.T) {
		r := rdataReader{err: ErrShortRDATA}
		assert.Nil(t, r.take(0))
		assert.Zero(t, r.uint16())
		assert.Zero(t, r.uint48())
		assert.Empty(t, r.name())
	})
	t.Run("uint48", func(t *testing.T) {
		r := rdataReader{b: fromHex(t, "ffffffffffff")}
		assert.Equal(t, uint64(1<<48-1), r.uint48())
	})
}

func TestVerify(t *testing.T) {
	key := newTestKey(t)
	msg, err := buildUpdate(0x1234, testZone, nil)
	require.NoError(t, err)
	signed, mac := key.sign(msg, time.Unix(1788589641, 0), 0x1234)
	good, err := findTSIG(signed)
	require.NoError(t, err)

	t.Run("good", func(t *testing.T) {
		assert.NoError(t, key.verify(signed, good, nil))
	})
	t.Run("another key", func(t *testing.T) {
		rec := good
		rec.name = "other-key."
		assert.ErrorIs(t, key.verify(signed, rec, nil), ErrTSIGKey)
	})
	t.Run("another algorithm", func(t *testing.T) {
		rec := good
		rec.algo = "hmac-sha1."
		assert.ErrorIs(t, key.verify(signed, rec, nil), ErrTSIGKey)
	})
	t.Run("the server reports BADTIME", func(t *testing.T) {
		rec := good
		rec.rcode = 18
		err := key.verify(signed, rec, nil)
		assert.ErrorIs(t, err, ErrTSIGError)
		assert.Contains(t, err.Error(), "BADTIME")
	})
	t.Run("a MAC that does not verify", func(t *testing.T) {
		rec := good
		rec.mac = make([]byte, len(mac))
		assert.ErrorIs(t, key.verify(signed, rec, nil), ErrBadMAC)
	})
	t.Run("the wrong request MAC", func(t *testing.T) {
		assert.ErrorIs(t, key.verify(signed, good, []byte("nope")), ErrBadMAC)
	})
	t.Run("a record that is not where it should be", func(t *testing.T) {
		rec := good
		rec.rdataLen = len(signed)
		assert.ErrorIs(t, key.verify(signed, rec, nil), ErrTSIGPlacement)
	})
	t.Run("an owner name that was rewritten", func(t *testing.T) {
		other := make([]byte, len(signed))
		copy(other, signed)
		off := len(signed) - good.rdataLen - tsigRRFixedLen - len(key.nameWire)
		other[off+1] = 'x'
		rec := good
		assert.ErrorIs(t, key.verify(other, rec, nil), ErrTSIGPlacement)
	})
	t.Run("an owner name in another case still verifies", func(t *testing.T) {
		other := make([]byte, len(signed))
		copy(other, signed)
		off := len(signed) - good.rdataLen - tsigRRFixedLen - len(key.nameWire)
		other[off+1] = 'D'
		assert.NoError(t, key.verify(other, good, nil))
	})
}

func TestTSIGErrorName(t *testing.T) {
	assert.Equal(t, "BADSIG", tsigErrorName(16))
	assert.Equal(t, "BADTRUNC", tsigErrorName(22))
	assert.Equal(t, "TSIG error 99", tsigErrorName(99))
}

func TestDot(t *testing.T) {
	assert.Equal(t, ".", dot(""))
	assert.Equal(t, "a.", dot("a"))
	assert.Equal(t, "a.", dot("a."))
}

func TestBuildUpdateGolden(t *testing.T) {
	// A header carrying the UPDATE opcode, one zone question, no
	// prerequisites and the counted update records.
	header := func(updates string) string { return "1234" + "2800" + "0001" + "0000" + updates + "0000" }

	cases := []struct {
		name    string
		zone    string
		changes []change
		want    string
	}{
		{
			name:    "delete an A RRset",
			zone:    testZone,
			changes: []change{deleteRRset("host.home.lan.", dnsmessage.TypeA)},
			want: header("0001") + wireHomeLan + "00060001" +
				wireHostHomeLan + "0001" + "00ff" + "00000000" + "0000",
		},
		{
			name: "replace an A record",
			zone: testZone,
			changes: []change{
				deleteRRset("host.home.lan.", dnsmessage.TypeA),
				addRecord("host.home.lan.", dnsmessage.TypeA, 300, []byte{10, 0, 0, 5}),
			},
			want: header("0002") + wireHomeLan + "00060001" +
				wireHostHomeLan + "0001" + "00ff" + "00000000" + "0000" +
				wireHostHomeLan + "0001" + "0001" + "0000012c" + "0004" + "0a000005",
		},
		{
			name: "replace an AAAA record",
			zone: testZone,
			changes: []change{
				deleteRRset("host.home.lan.", dnsmessage.TypeAAAA),
				addRecord("host.home.lan.", dnsmessage.TypeAAAA, 300,
					netip.MustParseAddr("2001:db8::1").AsSlice()),
			},
			want: header("0002") + wireHomeLan + "00060001" +
				wireHostHomeLan + "001c" + "00ff" + "00000000" + "0000" +
				wireHostHomeLan + "001c" + "0001" + "0000012c" + "0010" +
				"20010db8000000000000000000000001",
		},
		{
			name: "replace a PTR record",
			zone: "0.0.10.in-addr.arpa.",
			changes: []change{
				deleteRRset("5.0.0.10.in-addr.arpa.", dnsmessage.TypePTR),
				addRecord("5.0.0.10.in-addr.arpa.", dnsmessage.TypePTR, 300, fromHex(t, wireHostHomeLan)),
			},
			want: header("0002") + wireRevZone24 + "00060001" +
				wireRevPTR + "000c" + "00ff" + "00000000" + "0000" +
				wireRevPTR + "000c" + "0001" + "0000012c" + "000f" + wireHostHomeLan,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildUpdate(0x1234, tc.zone, tc.changes)
			require.NoError(t, err)
			assert.Equal(t, fromHex(t, tc.want), got)
		})
	}
}

func TestBuildUpdateErrors(t *testing.T) {
	t.Run("a zone name that is too long for the encoder", func(t *testing.T) {
		_, err := buildUpdate(1, strings.Repeat("a", 300), nil)
		assert.Error(t, err)
	})
	t.Run("a zone without a trailing dot", func(t *testing.T) {
		_, err := buildUpdate(1, "home.lan", nil)
		assert.Error(t, err)
	})
	t.Run("a record name that is too long for the encoder", func(t *testing.T) {
		_, err := buildUpdate(1, testZone, []change{deleteRRset(strings.Repeat("a", 300), dnsmessage.TypeA)})
		assert.Error(t, err)
	})
	t.Run("a record name without a trailing dot", func(t *testing.T) {
		_, err := buildUpdate(1, testZone, []change{deleteRRset("host.home.lan", dnsmessage.TypeA)})
		assert.Error(t, err)
	})
}

func TestForwardChanges(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.5")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")

	t.Run("one address", func(t *testing.T) {
		got := forwardChanges(job{name: "host.home.lan.", addrs: []netip.Addr{v4}}, 300)
		require.Len(t, got, 2)
		assert.Equal(t, deleteRRset("host.home.lan.", dnsmessage.TypeA), got[0])
		assert.Equal(t, addRecord("host.home.lan.", dnsmessage.TypeA, 300, v4.AsSlice()), got[1])
	})
	t.Run("several addresses share one delete", func(t *testing.T) {
		got := forwardChanges(job{name: "host.home.lan.", addrs: []netip.Addr{v6a, v6b}}, 60)
		require.Len(t, got, 3)
		assert.Equal(t, dnsmessage.ClassANY, got[0].class)
		assert.Equal(t, dnsmessage.TypeAAAA, got[0].rtype)
		assert.Equal(t, v6b.AsSlice(), got[2].data)
	})
	t.Run("a removal is the delete on its own", func(t *testing.T) {
		got := forwardChanges(job{name: "host.home.lan.", addrs: []netip.Addr{v4}, remove: true}, 300)
		assert.Equal(t, []change{deleteRRset("host.home.lan.", dnsmessage.TypeA)}, got)
	})
}

func TestReverseChanges(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.5")
	t.Run("replace", func(t *testing.T) {
		got, err := reverseChanges(job{name: "host.home.lan."}, addr, 300)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "5.0.0.10.in-addr.arpa.", got[0].name)
		assert.Equal(t, dnsmessage.ClassANY, got[0].class)
		assert.Equal(t, fromHex(t, wireHostHomeLan), got[1].data)
	})
	t.Run("remove", func(t *testing.T) {
		got, err := reverseChanges(job{name: "host.home.lan.", remove: true}, addr, 300)
		require.NoError(t, err)
		assert.Len(t, got, 1)
	})
	t.Run("a target name that cannot be packed", func(t *testing.T) {
		_, err := reverseChanges(job{name: "host.home.lan"}, addr, 300)
		assert.ErrorIs(t, err, ErrBadName)
	})
}

func TestRandomID(t *testing.T) {
	// Two draws being equal is a one in 65536 accident; a hundred all being
	// equal is a broken generator.
	seen := make(map[uint16]bool)
	for range 100 {
		seen[randomID()] = true
	}
	assert.Greater(t, len(seen), 1)
}

func TestAddressType(t *testing.T) {
	assert.Equal(t, dnsmessage.TypeA, addressType(netip.MustParseAddr("10.0.0.5")))
	assert.Equal(t, dnsmessage.TypeAAAA, addressType(netip.MustParseAddr("2001:db8::1")))
}

func TestUpdateAgainstFakeServer(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f)

	require.NoError(t, p.update(testZone, []change{deleteRRset("host.home.lan.", dnsmessage.TypeA)}))
	require.Len(t, f.received(), 1)

	// What reached the server has to be a signed message this package would
	// itself accept.
	rec, err := findTSIG(f.received()[0])
	require.NoError(t, err)
	assert.NoError(t, p.key.verify(f.received()[0], rec, nil))
}

func TestUpdateFailures(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(*fakeDNS)
		wantErr error
	}{
		{
			name:    "the answer is for another request",
			arrange: func(f *fakeDNS) { f.idOffset = 1 },
			wantErr: ErrResponseID,
		},
		{
			name:    "the answer is truncated",
			arrange: func(f *fakeDNS) { f.truncated = true },
			wantErr: ErrTruncated,
		},
		{
			name:    "the answer is not signed",
			arrange: func(f *fakeDNS) { f.unsigned = true },
			wantErr: ErrNoTSIG,
		},
		{
			name:    "the MAC has been tampered with",
			arrange: func(f *fakeDNS) { f.corruptAt = 8 },
			wantErr: ErrBadMAC,
		},
		{
			name:    "the server refuses the zone",
			arrange: func(f *fakeDNS) { f.rcode = dnsmessage.RCode(10) },
			wantErr: ErrRCode,
		},
		{
			name:    "the server never answers",
			arrange: func(f *fakeDNS) { f.ignore = attempts },
			wantErr: ErrNoAnswer,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeDNS(t, newTestKey(t))
			f.set(tc.arrange)
			p := newTestPlugin(t, f, "timeout:100ms")
			err := p.update(testZone, nil)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestUpdateRetriesOnce(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	f.set(func(f *fakeDNS) { f.ignore = 1 })
	p := newTestPlugin(t, f, "timeout:100ms")

	require.NoError(t, p.update(testZone, nil))
	assert.Len(t, f.received(), 2, "the first datagram was dropped, the second was answered")
}

func TestUpdateBuildFailure(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f)
	assert.Error(t, p.update("home.lan", nil), "a zone without a trailing dot cannot be encoded")
	assert.Empty(t, f.received())
}

func TestExchangeDialFailure(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f)
	p.server = "not an address"
	_, err := p.exchange([]byte{0})
	assert.ErrorContains(t, err, "dialling")
}

// Embedded interface is nil: only the methods roundTrip calls are
// implemented, so anything else panics rather than being silently wrong.
type stubConn struct {
	net.Conn
	deadlineErr error
	writeErr    error
	readErr     error
}

func (c stubConn) SetDeadline(time.Time) error { return c.deadlineErr }
func (c stubConn) Write(b []byte) (int, error) { return len(b), c.writeErr }
func (c stubConn) Read([]byte) (int, error)    { return 0, c.readErr }

func TestRoundTripConnFailures(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "timeout:50ms")
	boom := errors.New("boom")

	for _, tc := range []struct {
		name string
		conn stubConn
		want string
	}{
		{"the deadline cannot be set", stubConn{deadlineErr: boom}, "setting the deadline"},
		{"the write fails", stubConn{writeErr: boom}, "sending to"},
		{"the read fails for something other than the timeout", stubConn{readErr: boom}, "reading from"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.roundTrip(tc.conn, []byte{0})
			assert.ErrorContains(t, err, tc.want)
			assert.ErrorIs(t, err, boom)
		})
	}
}

func TestCheckResponseUnparseable(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f)
	assert.ErrorContains(t, p.checkResponse([]byte{1, 2}, nil, 1), "parsing the response")
}

func TestRCodeName(t *testing.T) {
	assert.Equal(t, "NOERROR", rcodeName(0))
	assert.Equal(t, "NOTZONE", rcodeName(10))
	assert.Equal(t, "RCODE 42", rcodeName(42))
}

func TestEnqueueDropsWhenFull(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "queue:1")
	now := time.Unix(1788589641, 0)
	p.now = func() time.Time { return now }

	p.enqueue(job{name: "a.home.lan."})
	assert.Zero(t, p.stats.dropped.Load())

	p.enqueue(job{name: "b.home.lan."})
	assert.Equal(t, uint64(1), p.stats.dropped.Load())
	first := p.drops.last

	// A second drop inside the interval is counted but not complained about
	// again, so a server that has stopped answering costs one line a minute.
	p.enqueue(job{name: "c.home.lan."})
	assert.Equal(t, uint64(2), p.stats.dropped.Load())
	assert.Equal(t, first, p.drops.last)

	now = now.Add(dropWarnInterval + time.Second)
	p.enqueue(job{name: "d.home.lan."})
	assert.Equal(t, uint64(3), p.stats.dropped.Load())
	assert.True(t, p.drops.last.After(first))
}

func TestTimeNowFallsBackToTheClock(t *testing.T) {
	p := &pluginState{}
	assert.WithinDuration(t, time.Now(), p.timeNow(), time.Minute)
}

func TestWorkerStopsCleanly(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f)
	p.start()

	p.enqueue(job{name: "host.home.lan.", addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}})
	require.Eventually(t, func() bool { return p.stats.sent.Load() == 1 }, time.Second, 5*time.Millisecond)

	p.stopWorker()
	select {
	case <-p.done:
	default:
		t.Fatal("the worker did not finish")
	}
	// Stopping twice must not close a closed channel.
	assert.NotPanics(t, p.stopWorker)
}

func TestApplyReverse(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "reverse:10.0.0.0/24", "reverse:2001:db8::/32")

	t.Run("an address inside a reverse network gets a second message", func(t *testing.T) {
		p.apply(job{name: "host.home.lan.", addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}})
		assert.Len(t, f.received(), 2)
	})
	t.Run("an address outside every reverse network does not", func(t *testing.T) {
		before := len(f.received())
		p.apply(job{name: "host.home.lan.", addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
		assert.Len(t, f.received(), before+1)
	})
	t.Run("an IPv6 address finds its own zone", func(t *testing.T) {
		before := len(f.received())
		p.apply(job{name: "host.home.lan.", addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}})
		assert.Len(t, f.received(), before+2)
	})
}

func TestApplyReverseNameFailure(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "reverse:10.0.0.0/24")
	// A name that no longer has its trailing dot cannot be packed into the
	// PTR record, so the reverse half is skipped and the forward half is not.
	p.apply(job{name: "host.home.lan", addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}})
	assert.Empty(t, f.received(), "neither message could be built")
	assert.Equal(t, uint64(1), p.stats.failed.Load())
}

func TestReverseZoneForPrefersTheFirstMatch(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "reverse:10.0.0.0/24", "reverse:10.0.0.0/16")
	zone, ok := p.reverseZoneFor(netip.MustParseAddr("10.0.0.5"))
	require.True(t, ok)
	assert.Equal(t, "0.0.10.in-addr.arpa.", zone)

	zone, ok = p.reverseZoneFor(netip.MustParseAddr("10.0.1.5"))
	require.True(t, ok)
	assert.Equal(t, "0.10.in-addr.arpa.", zone)

	_, ok = p.reverseZoneFor(netip.MustParseAddr("192.0.2.1"))
	assert.False(t, ok)
}

func TestSendUpdateCounters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*fakeDNS)
		counter func(*pluginState) uint64
	}{
		{"success", func(*fakeDNS) {}, func(p *pluginState) uint64 { return p.stats.sent.Load() }},
		{"truncated", func(f *fakeDNS) { f.truncated = true }, func(p *pluginState) uint64 { return p.stats.truncated.Load() }},
		{"refused", func(f *fakeDNS) { f.rcode = 5 }, func(p *pluginState) uint64 { return p.stats.refused.Load() }},
		{"failed", func(f *fakeDNS) { f.ignore = attempts }, func(p *pluginState) uint64 { return p.stats.failed.Load() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeDNS(t, newTestKey(t))
			f.set(tc.arrange)
			p := newTestPlugin(t, f, "timeout:100ms")
			p.sendUpdate(testZone, nil)
			assert.Equal(t, uint64(1), tc.counter(p))
		})
	}
}

func TestParseArgsDefaults(t *testing.T) {
	s, err := parseArgs([]string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:" + testKeySecret})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.53:53", s.server)
	assert.Equal(t, "home.lan.", s.zone)
	assert.Equal(t, uint32(defaultTTL), s.ttl)
	assert.Equal(t, defaultTimeout, s.timeout)
	assert.Equal(t, defaultQueueLen, s.queueLen)
	assert.True(t, s.removeOnRelease)
	assert.Empty(t, s.reverse)
	assert.Equal(t, "ddns-key.", s.key.name)
	assert.Equal(t, "hmac-sha256.", s.key.algo)
}

func TestParseArgsEverything(t *testing.T) {
	s, err := parseArgs([]string{
		"queue:5", "reverse:2001:db8::/32", "ttl:60", "algo:hmac-sha512",
		"key:ddns-key:" + testKeySecret, "zone:HOME.LAN.", "timeout:5s",
		"reverse:10.0.0.0/24", "server:[2001:db8::53]:5353", "remove-on-release:off",
	})
	require.NoError(t, err)
	assert.Equal(t, "[2001:db8::53]:5353", s.server)
	assert.Equal(t, "home.lan.", s.zone)
	assert.Equal(t, uint32(60), s.ttl)
	assert.Equal(t, 5*time.Second, s.timeout)
	assert.Equal(t, 5, s.queueLen)
	assert.False(t, s.removeOnRelease)
	assert.Equal(t, "hmac-sha512.", s.key.algo)
	require.Len(t, s.reverse, 2)
	assert.Equal(t, "8.b.d.0.1.0.0.2.ip6.arpa.", s.reverse[0].zone)
	assert.Equal(t, "0.0.10.in-addr.arpa.", s.reverse[1].zone)
}

func TestParseArgsErrors(t *testing.T) {
	base := []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:" + testKeySecret}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "server:<ip> is required"},
		{"no zone", []string{"server:10.0.0.53"}, "zone:<name> is required"},
		{"no key", []string{"server:10.0.0.53", "zone:home.lan"}, "key:<name>:<secret> is required"},
		{"unknown argument", with("nonsense"), "unknown argument"},
		{"a repeated argument", with("ttl:60", "ttl:90"), "ttl given more than once"},
		{"a repeated server", with("server:10.0.0.54"), "server given more than once"},
		{"a server that is a name", []string{"server:ns.example.com", "zone:home.lan"}, "has to be an IP address"},
		{"a server with a bad port", []string{"server:10.0.0.53:dns"}, "invalid port"},
		{"a server with port zero", []string{"server:10.0.0.53:0"}, "invalid port"},
		{"a zone that is not a name", []string{"server:10.0.0.53", "zone:home_lan"}, "invalid zone"},
		{"a key without a secret", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key"}, "needs <name>:<secret>"},
		{"a key without a name", []string{"server:10.0.0.53", "zone:home.lan", "key::secret"}, "needs <name>:<secret>"},
		{"a key name that is not a DNS name", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns..key:" + testKeySecret}, "key name"},
		{"a secret that is not base64", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:not base64"}, "not usable base64"},
		{"an empty secret", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:"}, "not usable base64"},
		{"an env: form with no variable name", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:env:"}, "needs the name of an environment variable"},
		{"an env: form naming an unset variable", []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:env:DDNS_NOT_SET_ANYWHERE"}, "is unset or empty"},
		{"an unknown algorithm", with("algo:hmac-md5"), "unknown TSIG algorithm"},
		{"a TTL that is not a number", with("ttl:soon"), "invalid ttl:"},
		{"a TTL over the limit", with("ttl:4294967295"), "invalid ttl:"},
		{"a reverse that is not a CIDR", with("reverse:10.0.0.0"), "it has to be a CIDR"},
		{"a reverse off a label boundary", with("reverse:10.0.0.0/25"), "multiple of 8"},
		{"a timeout that is not a duration", with("timeout:soon"), "want a positive duration"},
		{"a timeout of zero", with("timeout:0s"), "want a positive duration"},
		{"a queue that is not a number", with("queue:lots"), "want a number between"},
		{"a queue of zero", with("queue:0"), "want a number between"},
		{"a queue over the limit", with("queue:99999999"), "want a number between"},
		{"a remove-on-release that is neither", with("remove-on-release:maybe"), "want on or off"},
		{"a remove-on-release with nothing after it", with("remove-on-release:"), "want on or off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseArgs(tc.args)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestParseArgsRemoveOnRelease(t *testing.T) {
	base := []string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:" + testKeySecret}
	on, err := parseArgs(append(base, "remove-on-release:on"))
	require.NoError(t, err)
	assert.True(t, on.removeOnRelease)
}

func TestParseArgsKeyFromEnvironment(t *testing.T) {
	t.Setenv("DDNS_TEST_TSIG_KEY", testKeySecret)
	s, err := parseArgs([]string{"server:10.0.0.53", "zone:home.lan", "key:ddns-key:env:DDNS_TEST_TSIG_KEY"})
	require.NoError(t, err)
	assert.Equal(t, "ddns-key.", s.key.name)
	assert.NotContains(t, knownArgs(), testKeySecret)
}

func TestSetup(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	good := []string{"server:" + f.addr(), "zone:home.lan", "key:ddns-key:" + testKeySecret}

	t.Run("DHCPv4", func(t *testing.T) {
		h, err := setup4(good...)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
	t.Run("DHCPv6", func(t *testing.T) {
		h, err := setup6(good...)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
	t.Run("DHCPv4 with a bad argument", func(t *testing.T) {
		_, err := setup4("nonsense")
		assert.Error(t, err)
	})
	t.Run("DHCPv6 with a bad argument", func(t *testing.T) {
		_, err := setup6("nonsense")
		assert.Error(t, err)
	})
}

func v4(t *testing.T, mtype dhcpv4.MessageType, mods ...dhcpv4.Modifier) (*dhcpv4.DHCPv4, *dhcpv4.DHCPv4) {
	t.Helper()
	req, err := dhcpv4.New(append([]dhcpv4.Modifier{
		dhcpv4.WithHwAddr(testMAC),
		dhcpv4.WithMessageType(mtype),
	}, mods...)...)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	return req, resp
}

func withFQDN4(flags byte, name []byte) dhcpv4.Modifier {
	return func(d *dhcpv4.DHCPv4) {
		d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionFQDN, append([]byte{flags, 0, 0}, name...)))
	}
}

func TestHandler4Lease(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "reverse:10.0.0.0/24")

	req, resp := v4(t, dhcpv4.MessageTypeRequest, dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
	resp.YourIPAddr = net.IP{10, 0, 0, 5}

	got, stop := p.Handler4(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop, "the chain carries on")

	p.drainOne(t)
	require.Len(t, f.received(), 2, "the forward zone and the reverse zone")
}

func TestHandler4Skips(t *testing.T) {
	longName := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		mods    []dhcpv4.Modifier
		respond func(*dhcpv4.DHCPv4)
	}{
		{
			name:    "an OFFER is not a lease",
			mods:    []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop"))},
			respond: func(r *dhcpv4.DHCPv4) { r.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer)) },
		},
		{
			name:    "no address in the response",
			mods:    []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop"))},
			respond: func(r *dhcpv4.DHCPv4) { r.YourIPAddr = nil },
		},
		{
			name:    "the unspecified address",
			mods:    []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop"))},
			respond: func(r *dhcpv4.DHCPv4) { r.YourIPAddr = net.IPv4zero },
		},
		{name: "no name at all"},
		{name: "a name that is not usable", mods: []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName(longName))}},
		{
			name: "a name in another zone",
			mods: []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop.example.com"))},
		},
		{
			name: "the client asked for no update",
			mods: []dhcpv4.Modifier{withFQDN4(fqdn4FlagN, []byte("laptop"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeDNS(t, newTestKey(t))
			p := newTestPlugin(t, f)
			req, resp := v4(t, dhcpv4.MessageTypeRequest, tc.mods...)
			resp.YourIPAddr = net.IP{10, 0, 0, 5}
			if tc.respond != nil {
				tc.respond(resp)
			}
			got, stop := p.Handler4(req, resp)
			assert.Same(t, resp, got)
			assert.False(t, stop)
			assert.Empty(t, p.queue)
		})
	}
	t.Run("no response to read an address from", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, _ := v4(t, dhcpv4.MessageTypeRequest)
		got, stop := p.Handler4(req, nil)
		assert.Nil(t, got)
		assert.False(t, stop)
	})
}

func TestHandler4Release(t *testing.T) {
	t.Run("removes the records", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f, "reverse:10.0.0.0/24")
		req, resp := v4(t, dhcpv4.MessageTypeRelease, dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
		req.ClientIPAddr = net.IP{10, 0, 0, 5}

		got, stop := p.Handler4(req, resp)
		assert.Same(t, resp, got)
		assert.False(t, stop)

		j := <-p.queue
		assert.True(t, j.remove)
		assert.Equal(t, "laptop.home.lan.", j.name)
	})
	t.Run("with remove-on-release off it does nothing", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f, "remove-on-release:off")
		req, resp := v4(t, dhcpv4.MessageTypeRelease, dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
		req.ClientIPAddr = net.IP{10, 0, 0, 5}
		p.Handler4(req, resp)
		assert.Empty(t, p.queue)
	})
	t.Run("a release without ciaddr names no lease", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, resp := v4(t, dhcpv4.MessageTypeRelease, dhcpv4.WithOption(dhcpv4.OptHostName("laptop")))
		p.Handler4(req, resp)
		assert.Empty(t, p.queue)
	})
	t.Run("a release without a name", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, resp := v4(t, dhcpv4.MessageTypeRelease)
		req.ClientIPAddr = net.IP{10, 0, 0, 5}
		p.Handler4(req, resp)
		assert.Empty(t, p.queue)
	})
}

func TestHostname4(t *testing.T) {
	wire := append([]byte{6}, append([]byte("laptop"), 0)...)
	cases := []struct {
		name       string
		mods       []dhcpv4.Modifier
		want       string
		wantWanted bool
	}{
		{name: "nothing at all", wantWanted: true},
		{
			name:       "option 12 only",
			mods:       []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop"))},
			want:       "laptop",
			wantWanted: true,
		},
		{
			name:       "option 81 in ASCII wins over option 12",
			mods:       []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("other")), withFQDN4(0, []byte("laptop"))},
			want:       "laptop",
			wantWanted: true,
		},
		{
			name:       "option 81 in wire form",
			mods:       []dhcpv4.Modifier{withFQDN4(fqdn4FlagE, wire)},
			want:       "laptop.",
			wantWanted: true,
		},
		{
			name:       "an option 81 with only the flags falls through",
			mods:       []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop")), withFQDN4(0, nil)},
			want:       "laptop",
			wantWanted: true,
		},
		{
			name:       "a malformed wire name falls back to option 12",
			mods:       []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop")), withFQDN4(fqdn4FlagE, []byte{0xc0, 0x0c})},
			want:       "laptop",
			wantWanted: true,
		},
		{
			name: "the N flag means no update",
			mods: []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("laptop")), withFQDN4(fqdn4FlagN, []byte("laptop"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := v4(t, dhcpv4.MessageTypeRequest, tc.mods...)
			name, wanted := hostname4(req)
			assert.Equal(t, tc.wantWanted, wanted)
			assert.Equal(t, tc.want, name)
		})
	}
}

func TestAddress4(t *testing.T) {
	addr, ok := address4(net.IP{10, 0, 0, 5})
	require.True(t, ok)
	assert.Equal(t, "10.0.0.5", addr.String())

	_, ok = address4(nil)
	assert.False(t, ok)
	_, ok = address4(net.IPv4zero)
	assert.False(t, ok)
}

func v6(t *testing.T, mods ...dhcpv6.Modifier) (*dhcpv6.Message, *dhcpv6.Message) {
	t.Helper()
	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: testMAC}
	req, err := dhcpv6.NewMessage(append([]dhcpv6.Modifier{dhcpv6.WithClientID(duid)}, mods...)...)
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	return req, resp
}

func withIANA(addrs ...string) dhcpv6.Modifier {
	return func(m dhcpv6.DHCPv6) {
		msg, ok := m.(*dhcpv6.Message)
		if !ok {
			return
		}
		var opts dhcpv6.IdentityOptions
		for _, a := range addrs {
			opts.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP(a), PreferredLifetime: time.Hour, ValidLifetime: time.Hour})
		}
		msg.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}, Options: opts})
	}
}

func withFQDN6(flags uint8, labels ...string) dhcpv6.Modifier {
	return func(m dhcpv6.DHCPv6) {
		msg, ok := m.(*dhcpv6.Message)
		if !ok {
			return
		}
		msg.AddOption(&dhcpv6.OptFQDN{Flags: flags, DomainName: &rfc1035label.Labels{Labels: labels}})
	}
}

func TestHandler6Lease(t *testing.T) {
	f := startFakeDNS(t, newTestKey(t))
	p := newTestPlugin(t, f, "reverse:2001:db8::/32")

	req, resp := v6(t, withFQDN6(0, "laptop"))
	withIANA("2001:db8::1", "2001:db8::2")(resp)

	got, stop := p.Handler6(req, resp)
	assert.Same(t, resp, got)
	assert.False(t, stop)

	j := <-p.queue
	assert.Equal(t, "laptop.home.lan.", j.name)
	require.Len(t, j.addrs, 2)

	p.apply(j)
	assert.Len(t, f.received(), 3, "one forward message and one reverse message per address")
}

func TestHandler6Skips(t *testing.T) {
	cases := []struct {
		name     string
		reqMods  []dhcpv6.Modifier
		respMods []dhcpv6.Modifier
		advert   bool
	}{
		{name: "an Advertise is not a lease", reqMods: []dhcpv6.Modifier{withFQDN6(0, "laptop")}, respMods: []dhcpv6.Modifier{withIANA("2001:db8::1")}, advert: true},
		{name: "no addresses", reqMods: []dhcpv6.Modifier{withFQDN6(0, "laptop")}},
		{name: "no FQDN option", respMods: []dhcpv6.Modifier{withIANA("2001:db8::1")}},
		{name: "the N flag means no update", reqMods: []dhcpv6.Modifier{withFQDN6(fqdn6FlagN, "laptop")}, respMods: []dhcpv6.Modifier{withIANA("2001:db8::1")}},
		{name: "a name in another zone", reqMods: []dhcpv6.Modifier{withFQDN6(0, "laptop", "example", "com")}, respMods: []dhcpv6.Modifier{withIANA("2001:db8::1")}},
		{name: "an IA_NA holding no usable address", reqMods: []dhcpv6.Modifier{withFQDN6(0, "laptop")}, respMods: []dhcpv6.Modifier{withIANA("::")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeDNS(t, newTestKey(t))
			p := newTestPlugin(t, f)
			req, resp := v6(t, tc.reqMods...)
			for _, mod := range tc.respMods {
				mod(resp)
			}
			if tc.advert {
				resp.MessageType = dhcpv6.MessageTypeAdvertise
			}
			got, stop := p.Handler6(req, resp)
			assert.Same(t, resp, got)
			assert.False(t, stop)
			assert.Empty(t, p.queue)
		})
	}
	t.Run("no response", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, _ := v6(t, withFQDN6(0, "laptop"))
		got, stop := p.Handler6(req, nil)
		assert.Nil(t, got)
		assert.False(t, stop)
	})
	t.Run("a request that cannot be decapsulated", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		relay := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
		got, stop := p.Handler6(relay, nil)
		assert.Nil(t, got)
		assert.False(t, stop)
	})
}

func TestHandler6Release(t *testing.T) {
	t.Run("removes the records named in the Release", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, resp := v6(t, withFQDN6(0, "laptop"), withIANA("2001:db8::1"))
		req.MessageType = dhcpv6.MessageTypeRelease

		p.Handler6(req, resp)
		j := <-p.queue
		assert.True(t, j.remove)
		assert.Equal(t, "laptop.home.lan.", j.name)
	})
	t.Run("with remove-on-release off it does nothing", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f, "remove-on-release:off")
		req, resp := v6(t, withFQDN6(0, "laptop"), withIANA("2001:db8::1"))
		req.MessageType = dhcpv6.MessageTypeRelease
		p.Handler6(req, resp)
		assert.Empty(t, p.queue)
	})
	t.Run("a Release naming no address", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, resp := v6(t, withFQDN6(0, "laptop"))
		req.MessageType = dhcpv6.MessageTypeRelease
		p.Handler6(req, resp)
		assert.Empty(t, p.queue)
	})
	t.Run("a Release without a name", func(t *testing.T) {
		f := startFakeDNS(t, newTestKey(t))
		p := newTestPlugin(t, f)
		req, resp := v6(t, withIANA("2001:db8::1"))
		req.MessageType = dhcpv6.MessageTypeRelease
		p.Handler6(req, resp)
		assert.Empty(t, p.queue)
	})
}

func TestHostname6(t *testing.T) {
	t.Run("an option with no name", func(t *testing.T) {
		req, _ := v6(t)
		req.AddOption(&dhcpv6.OptFQDN{Flags: 0})
		name, wanted := hostname6(req)
		assert.True(t, wanted)
		assert.Empty(t, name)
	})
}

func TestAddress6(t *testing.T) {
	addr, ok := address6(net.ParseIP("2001:db8::1"))
	require.True(t, ok)
	assert.Equal(t, "2001:db8::1", addr.String())

	for _, tc := range []struct {
		name string
		ip   net.IP
	}{
		{"nothing", nil},
		{"the unspecified address", net.IPv6unspecified},
		{"an IPv4 address in four octets", net.IP{10, 0, 0, 5}},
		{"an IPv4 address mapped into IPv6", net.ParseIP("10.0.0.5")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := address6(tc.ip)
			assert.False(t, ok)
		})
	}
}

func TestInnerMessage(t *testing.T) {
	_, err := innerMessage(nil)
	assert.Error(t, err)
}
