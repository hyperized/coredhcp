// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build integration

// These tests drive the plugin's handlers against a real name server that
// accepts TSIG-signed RFC 2136 updates, then ask that server what it now
// holds. `make test-ddns` brings up Knot DNS and runs them in compose;
// without DDNS_SERVER they skip.
//
// The environment they read:
//
//	DDNS_SERVER        host:port of the name server
//	DDNS_ZONE          the forward zone, which has to accept the key
//	DDNS_KEY           the TSIG key name
//	DDNS_TSIG_SECRET   the base64 secret
//	DDNS_REVERSE4      an IPv4 CIDR whose reverse zone accepts the key
//	DDNS_REVERSE6      an IPv6 CIDR whose reverse zone accepts the key

package ddns

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
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

// settle is how long a record is waited for. Knot applies an update before it
// answers, so this only ever covers the hop between the two.
const settle = 10 * time.Second

// serverAddr returns DDNS_SERVER as a literal address with a port.
//
// The plugin refuses a server: argument that is a name, on purpose: a DHCP
// server that looks its name server up through the resolver it feeds has a
// bootstrap problem. In compose the server is reached by its service name, so
// the resolving happens here instead, once.
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
	if _, parseErr := netip.ParseAddr(host); parseErr == nil {
		return net.JoinHostPort(host, port)
	}
	ips, err := net.LookupIP(host)
	require.NoError(t, err, "resolving DDNS_SERVER host %q", host)
	require.NotEmpty(t, ips)
	return net.JoinHostPort(ips[0].String(), port)
}

// integrationPlugin builds an instance against the configured server, with
// its worker running.
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

// testHost returns a host name nothing else in this zone is using, so a rerun
// or a shared server cannot decide the outcome.
func testHost(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("itest-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// testAddr4 returns an address inside DDNS_REVERSE4, keyed off the process so
// two runs on one server do not fight over the same PTR.
func testAddr4(t *testing.T) netip.Addr {
	t.Helper()
	pfx, err := netip.ParsePrefix(os.Getenv("DDNS_REVERSE4"))
	require.NoError(t, err)
	b := pfx.Addr().As4()
	b[3] = byte(os.Getpid()%200 + 20)
	return netip.AddrFrom4(b)
}

// testAddr6 does the same inside DDNS_REVERSE6.
func testAddr6(t *testing.T) netip.Addr {
	t.Helper()
	pfx, err := netip.ParsePrefix(os.Getenv("DDNS_REVERSE6"))
	require.NoError(t, err)
	b := pfx.Addr().As16()
	b[15] = byte(os.Getpid()%200 + 20)
	return netip.AddrFrom16(b)
}

// ask sends one ordinary query and returns the answer section.
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

// addresses returns the A and AAAA records of an answer section.
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

// targets returns the PTR targets of an answer section.
func targets(answers []dnsmessage.Resource) []string {
	var out []string
	for _, r := range answers {
		if body, ok := r.Body.(*dnsmessage.PTRResource); ok {
			out = append(out, body.PTR.String())
		}
	}
	return out
}

// dnsmessage has no body type for type 49, so Knot's answer comes back as
// opaque RDATA, which is also how this plugin writes it.
func dhcids(answers []dnsmessage.Resource) []string {
	var out []string
	for _, r := range answers {
		body, ok := r.Body.(*dnsmessage.UnknownResource)
		if !ok || body.Type != typeDHCID {
			continue
		}
		out = append(out, hex.EncodeToString(body.Data))
	}
	return out
}

func dhcidOf(t *testing.T, mac net.HardwareAddr, fqdn string) string {
	t.Helper()
	req, err := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest))
	require.NoError(t, err)
	rdata, err := identity4(req).record(fqdn)
	require.NoError(t, err)
	return hex.EncodeToString(rdata)
}

// ack4 hands the worker a lease; what it does with it is read back out of
// Knot with eventually.
func ack4(t *testing.T, p *pluginState, mac net.HardwareAddr, host string, addr netip.Addr) {
	t.Helper()
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
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
}

func release4(t *testing.T, p *pluginState, mac net.HardwareAddr, host string, addr netip.Addr) {
	t.Helper()
	rel, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		dhcpv4.WithOption(dhcpv4.OptHostName(host)),
	)
	require.NoError(t, err)
	rel.ClientIPAddr = net.IP(addr.AsSlice())
	_, stop := p.Handler4(rel, nil)
	require.False(t, stop)
}

// eventually waits for the server to agree with want.
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
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}

	ack4(t, p, mac, host, addr)

	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, []string{addr.String()})
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, []string{fqdn})
	// Knot serves type 49 like any other, so this is the record the next
	// client's prerequisite will be weighed against.
	eventually(t, server, fqdn, typeDHCID, dhcids, []string{dhcidOf(t, mac, fqdn)})

	// The same client asking again is refused on the first prerequisite and
	// taken on the second, which is the whole of RFC 4703 section 5.3.
	next := netip.AddrFrom4([4]byte{addr.As4()[0], addr.As4()[1], addr.As4()[2], addr.As4()[3] + 1})
	ack4(t, p, mac, host, next)
	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, []string{next.String()})
	eventually(t, server, fqdn, typeDHCID, dhcids, []string{dhcidOf(t, mac, fqdn)})

	release4(t, p, mac, host, next)

	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, nil)
	eventually(t, server, fqdn, typeDHCID, dhcids, nil)
	eventually(t, server, ptrName(next), dnsmessage.TypePTR, targets, nil)
}

// TestIntegrationNameHeldByAnotherClient is the finding this plugin was
// audited for, run against a real name server.
func TestIntegrationNameHeldByAnotherClient(t *testing.T) {
	p := integrationPlugin(t)
	server := p.server
	host := testHost(t)
	addr := testAddr4(t)
	fqdn := host + "." + p.zone
	holder := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	intruder := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}

	ack4(t, p, holder, host, addr)
	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, []string{addr.String()})

	// Knot refuses both of the messages that follow, on the prerequisites.
	other := netip.AddrFrom4([4]byte{addr.As4()[0], addr.As4()[1], addr.As4()[2], addr.As4()[3] + 2})
	ack4(t, p, intruder, host, other)
	require.Eventually(t, func() bool { return p.stats.conflicts.Load() == 1 }, settle, 100*time.Millisecond)

	assert.Equal(t, []string{addr.String()}, addresses(ask(t, server, fqdn, dnsmessage.TypeA)),
		"the name still points at the client that holds it")
	assert.Equal(t, []string{dhcidOf(t, holder, fqdn)}, dhcids(ask(t, server, fqdn, typeDHCID)))
	assert.Empty(t, targets(ask(t, server, ptrName(other), dnsmessage.TypePTR)),
		"a refused forward update writes no PTR either")

	// The register drops this on the packet path, so nothing even reaches Knot.
	before := p.stats.sent.Load()
	release4(t, p, intruder, host, addr)
	assert.Equal(t, []string{addr.String()}, addresses(ask(t, server, fqdn, dnsmessage.TypeA)))
	assert.Equal(t, before, p.stats.sent.Load(), "a release from a stranger sends nothing at all")

	release4(t, p, holder, host, addr)
	eventually(t, server, fqdn, dnsmessage.TypeA, addresses, nil)
}

func TestIntegrationProtectedName(t *testing.T) {
	host := testHost(t)
	p, err := setupState(
		"server:"+serverAddr(t),
		"zone:"+os.Getenv("DDNS_ZONE"),
		"key:"+os.Getenv("DDNS_KEY")+":"+os.Getenv("DDNS_TSIG_SECRET"),
		"protect:"+host,
		"ttl:60",
		"timeout:5s",
	)
	require.NoError(t, err)
	t.Cleanup(p.stopWorker)

	ack4(t, p, net.HardwareAddr{0x02, 0, 0, 0, 0, 3}, host, testAddr4(t))

	assert.Empty(t, addresses(ask(t, p.server, host+"."+p.zone, dnsmessage.TypeA)))
	assert.Zero(t, p.stats.sent.Load(), "a protected name never reaches the name server")
}

// TestIntegrationLease6 is TestIntegrationLease4 for DHCPv6, where the
// addresses come out of the IA_NA of the reply being built.
func TestIntegrationLease6(t *testing.T) {
	p := integrationPlugin(t)
	server := p.server
	host := testHost(t)
	addr := testAddr6(t)
	fqdn := host + "." + p.zone

	// A client identifier is not optional here: it is the identifier the
	// DHCID is built from, and RFC 8415 section 16 has a client send one in
	// every message anyway.
	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 4}}
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
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

	// Over DHCPv6 the identifier of RFC 4701 is the DUID, under type code 2.
	wantDHCID, err := identity6(req).record(fqdn)
	require.NoError(t, err)
	eventually(t, server, fqdn, typeDHCID, dhcids, []string{hex.EncodeToString(wantDHCID)})

	rel, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	rel.MessageType = dhcpv6.MessageTypeRelease
	rel.AddOption(&dhcpv6.OptFQDN{DomainName: labels(host)})
	rel.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}, Options: ia})

	_, stop = p.Handler6(rel, resp)
	require.False(t, stop)

	eventually(t, server, fqdn, dnsmessage.TypeAAAA, addresses, nil)
	eventually(t, server, fqdn, typeDHCID, dhcids, nil)
	eventually(t, server, ptrName(addr), dnsmessage.TypePTR, targets, nil)
}

// TestIntegrationRefusedZone checks what a server really does with a zone it
// does not hold. Knot has no key for such a zone and so cannot sign the
// refusal: the answer comes back unsigned, carrying NOTAUTH. That has to be
// reported as an unsigned answer, with the code it claimed named alongside,
// and never as a verified NOTAUTH.
func TestIntegrationRefusedZone(t *testing.T) {
	p := integrationPlugin(t)
	err := p.update(t.Context(), "not-a-zone-we-hold.example.", nil,
		[]change{deleteRRset("host.not-a-zone-we-hold.example.", dnsmessage.TypeA)})
	require.ErrorIs(t, err, ErrNoTSIG)
	assert.Contains(t, err.Error(), "NOTAUTH")
}

// TestIntegrationWrongKey checks that a server which rejects the signature is
// heard correctly. Knot answers a bad MAC with a TSIG carrying BADKEY or
// BADSIG rather than with a signed refusal, and that has to come back as a
// TSIG failure, not as a MAC this side computed wrongly.
func TestIntegrationWrongKey(t *testing.T) {
	good := integrationPlugin(t)
	bad, err := newPluginState(
		"server:"+serverAddr(t),
		"zone:"+os.Getenv("DDNS_ZONE"),
		"key:"+os.Getenv("DDNS_KEY")+":bm90LXRoZS1yaWdodC1zZWNyZXQtYXQtYWxsLW5vcGU=",
		"timeout:5s",
	)
	require.NoError(t, err)

	err = bad.update(t.Context(), good.zone, nil, []change{deleteRRset("nobody."+good.zone, dnsmessage.TypeA)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTSIGError)
}

// labels turns a single host name into the form option 39 carries.
func labels(host string) *rfc1035label.Labels {
	return &rfc1035label.Labels{Labels: []string{host}}
}
