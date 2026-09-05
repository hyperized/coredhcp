// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build integration

// These tests drive the plugin against a real name server. `make test-ddns`
// brings up Knot DNS and runs them in compose; without DDNS_SERVER they skip.
//
// Environment read:
//
//	DDNS_SERVER        host:port of the name server
//	DDNS_ZONE          the forward zone, which has to accept the key
//	DDNS_KEY           the TSIG key name
//	DDNS_TSIG_SECRET   the base64 secret
//	DDNS_REVERSE4      an IPv4 CIDR whose reverse zone accepts the key
//	DDNS_REVERSE6      an IPv6 CIDR whose reverse zone accepts the key

package ddns

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Knot applies an update before it answers, so this only covers the hop
// between the two.
const settle = 10 * time.Second

// The plugin requires a literal server IP; compose reaches the name server
// by service name, so the resolution happens here once instead.
func serverAddr(t *testing.T) string {
	t.Helper()
	server := os.Getenv("DDNS_SERVER")
	if server == "" {
		t.Skip("DDNS_SERVER is not set, skipping: this test needs a real name server")
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "53"
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(host, port)
	}
	ips, err := net.LookupIP(host)
	require.NoError(t, err, "resolving DDNS_SERVER host %q", host)
	require.NotEmpty(t, ips)
	return net.JoinHostPort(ips[0].String(), port)
}

func integrationPlugin(t *testing.T) *pluginState {
	t.Helper()
	p, err := setupState(
		"server:"+serverAddr(t),
		"zone:"+os.Getenv("DDNS_ZONE"),
		"key:"+os.Getenv("DDNS_KEY")+":"+os.Getenv("DDNS_TSIG_SECRET"),
		"reverse:"+os.Getenv("DDNS_REVERSE4"),
		"reverse:"+os.Getenv("DDNS_REVERSE6"),
		"ttl:60",
		"timeout:5s",
	)
	require.NoError(t, err)
	t.Cleanup(p.stopWorker)
	return p
}

// Unique, so a rerun or a shared server can't decide the outcome.
func testHost(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("itest-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// Keyed off the process, so two runs on one server don't fight over the same PTR.
func testAddr4(t *testing.T) netip.Addr {
	t.Helper()
	pfx, err := netip.ParsePrefix(os.Getenv("DDNS_REVERSE4"))
	require.NoError(t, err)
	b := pfx.Addr().As4()
	b[3] = byte(os.Getpid()%200 + 20)
	return netip.AddrFrom4(b)
}

func testAddr6(t *testing.T) netip.Addr {
	t.Helper()
	pfx, err := netip.ParsePrefix(os.Getenv("DDNS_REVERSE6"))
	require.NoError(t, err)
	b := pfx.Addr().As16()
	b[15] = byte(os.Getpid()%200 + 20)
	return netip.AddrFrom16(b)
}

func ask(t *testing.T, server, name string, qtype dnsmessage.Type) []dnsmessage.Resource {
	t.Helper()
	qname, err := dnsmessage.NewName(name)
	require.NoError(t, err)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: randomID()})
	require.NoError(t, b.StartQuestions())
	require.NoError(t, b.Question(dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}))
	msg, err := b.Finish()
	require.NoError(t, err)

	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	require.NoError(t, err)
	defer func() { assert.NoError(t, conn.Close()) }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	var parser dnsmessage.Parser
	_, err = parser.Start(buf[:n])
	require.NoError(t, err)
	require.NoError(t, parser.SkipAllQuestions())
	answers, err := parser.AllAnswers()
	require.NoError(t, err)
	return answers
}

func addresses(answers []dnsmessage.Resource) []string {
	var out []string
	for _, r := range answers {
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(body.A).String())
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(body.AAAA).String())
		}
	}
	return out
}

func targets(answers []dnsmessage.Resource) []string {
	var out []string
	for _, r := range answers {
		if body, ok := r.Body.(*dnsmessage.PTRResource); ok {
			out = append(out, body.PTR.String())
		}
	}
	return out
}

func eventually(t *testing.T, server, name string, qtype dnsmessage.Type, extract func([]dnsmessage.Resource) []string, want []string) {
	t.Helper()
	var got []string
	require.Eventually(t, func() bool {
		got = extract(ask(t, server, name, qtype))
		return assert.ObjectsAreEqual(want, got)
	}, settle, 200*time.Millisecond, "%s %s: wanted %v, last saw %v", name, qtype, want, got)
}

func TestIntegrationLease4(t *testing.T) {
	p := integrationPlugin(t)
	server := p.server
	host := testHost(t)
	addr := testAddr4(t)
	fqdn := host + "." + p.zone

	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptHostName(host)),
	)
	require.NoError(t, err)
	resp, err := dhcpv4.NewReplyFromRequest(req)
	require.NoError(t, err)
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.YourIPAddr = net.IP(addr.AsSlice())

	got, stop := p.Handler4(req, resp)
	require.Same(t, resp, got)
	require.False(t, stop)

	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, []string{addr.String()})
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, []string{fqdn})

	// The same client giving the lease back takes both records with it.
	rel, err := dhcpv4.New(
		dhcpv4.WithHwAddr(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		dhcpv4.WithOption(dhcpv4.OptHostName(host)),
	)
	require.NoError(t, err)
	rel.ClientIPAddr = net.IP(addr.AsSlice())

	_, stop = p.Handler4(rel, resp)
	require.False(t, stop)

	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, nil)
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, nil)
}

func TestIntegrationLease6(t *testing.T) {
	p := integrationPlugin(t)
	server := p.server
	host := testHost(t)
	addr := testAddr6(t)
	fqdn := host + "." + p.zone

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.AddOption(&dhcpv6.OptFQDN{DomainName: labels(host)})

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply
	var ia dhcpv6.IdentityOptions
	ia.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.IP(addr.AsSlice()),
		PreferredLifetime: time.Hour,
		ValidLifetime:     time.Hour,
	})
	resp.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}, Options: ia})

	got, stop := p.Handler6(req, resp)
	require.Same(t, resp, got)
	require.False(t, stop)

	eventually(t, server, fqdn, dnsmessage.TypeAAAA, addresses, []string{addr.String()})
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, []string{fqdn})

	rel, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	rel.MessageType = dhcpv6.MessageTypeRelease
	rel.AddOption(&dhcpv6.OptFQDN{DomainName: labels(host)})
	rel.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}, Options: ia})

	_, stop = p.Handler6(rel, resp)
	require.False(t, stop)

	eventually(t, server, fqdn, dnsmessage.TypeAAAA, addresses, nil)
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, nil)
}

// Knot has no key for a zone it doesn't hold, so it can't sign the refusal:
// the answer comes back unsigned, carrying NOTAUTH, and must be reported as such.
func TestIntegrationRefusedZone(t *testing.T) {
	p := integrationPlugin(t)
	err := p.update("not-a-zone-we-hold.example.",
		[]change{deleteRRset("host.not-a-zone-we-hold.example.", dnsmessage.TypeA)})
	require.ErrorIs(t, err, ErrNoTSIG)
	assert.Contains(t, err.Error(), "NOTAUTH")
}

// Knot answers a bad MAC with a TSIG BADKEY/BADSIG, not a signed refusal;
// that must come back as a TSIG failure, not a MAC this side computed wrongly.
func TestIntegrationWrongKey(t *testing.T) {
	good := integrationPlugin(t)
	bad, err := newPluginState(
		"server:"+serverAddr(t),
		"zone:"+os.Getenv("DDNS_ZONE"),
		"key:"+os.Getenv("DDNS_KEY")+":bm90LXRoZS1yaWdodC1zZWNyZXQtYXQtYWxsLW5vcGU=",
		"timeout:5s",
	)
	require.NoError(t, err)

	err = bad.update(good.zone, []change{deleteRRset("nobody."+good.zone, dnsmessage.TypeA)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTSIGError)
}

func labels(host string) *rfc1035label.Labels {
	return &rfc1035label.Labels{Labels: []string{host}}
}
