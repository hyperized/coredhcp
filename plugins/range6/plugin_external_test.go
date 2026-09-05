// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6_test

import (
	"bytes"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"

	// The "sqlite" driver is registered by range6's own storage.go import,
	// which is already pulled in below.
	"github.com/coredhcp/coredhcp/plugins/range6"
)

const (
	poolFirst = "2001:db8:1::100"
	poolLast  = "2001:db8:1::1ff"
	leaseTime = "12h"
)

var (
	iaid1 = [4]byte{0x00, 0x00, 0x00, 0x01}
	iaid2 = [4]byte{0x00, 0x00, 0x00, 0x02}
)

// TestMain silences the console for the whole package. The plugin logs a line
// per exchange, and a full run makes thousands of them.
func TestMain(m *testing.M) {
	logger.WithNoStdOutErr()
	os.Exit(m.Run())
}

// setupPlugin builds a plugin instance over a fresh database in the test's
// temp dir.
//
// Every instance gets a sweep interval far longer than a test run. Setup6
// starts the background sweeper and nothing in the public API can stop it, so
// the black-box tests rely on it never ticking; the timing of reclamation
// itself is tested against the clock seam in plugin_internal_test.go.
func setupPlugin(t *testing.T) handler.Handler6 {
	t.Helper()
	return setupPool(t, poolLast)
}

// setupPool builds one over a pool that ends at last, which is how a test asks
// for a pool small enough to run dry.
func setupPool(t *testing.T, last string, opts ...string) handler.Handler6 {
	t.Helper()
	return setupPoolAt(t, filepath.Join(t.TempDir(), "leases6.sqlite3"), last, opts...)
}

// setupPoolAt is the same over a named database file, so a test can start a
// second instance on the one the first left behind.
func setupPoolAt(t *testing.T, db, last string, opts ...string) handler.Handler6 {
	t.Helper()
	args := append([]string{db, poolFirst, last, leaseTime, "sweep:1h"}, opts...)
	h, err := range6.Plugin.Setup6(args...)
	require.NoError(t, err)
	require.NotNil(t, h)
	return h
}

// testDUID builds a link-layer DUID, distinct per id so one test can drive
// several clients.
func testDUID(id byte) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, id},
	}
}

// newIANA builds an IA_NA option carrying the given addresses, which is both
// how a client hints at an address and how it names the ones it is giving up.
func newIANA(iaid [4]byte, addrs ...net.IP) *dhcpv6.OptIANA {
	ia := &dhcpv6.OptIANA{IaId: iaid}
	for _, addr := range addrs {
		ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: addr})
	}
	return ia
}

func newRequest(t *testing.T, mtype dhcpv6.MessageType, duid dhcpv6.DUID, ianas ...*dhcpv6.OptIANA) *dhcpv6.Message {
	t.Helper()
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	req.MessageType = mtype
	for _, ia := range ianas {
		req.AddOption(ia)
	}
	return req
}

// newResponse builds the response the server hands the plugin chain: an
// Advertise for a plain SOLICIT, a Reply for everything else.
func newResponse(req *dhcpv6.Message) *dhcpv6.Message {
	mtype := dhcpv6.MessageTypeReply
	if req.MessageType == dhcpv6.MessageTypeSolicit && req.GetOneOption(dhcpv6.OptionRapidCommit) == nil {
		mtype = dhcpv6.MessageTypeAdvertise
	}
	return &dhcpv6.Message{MessageType: mtype, TransactionID: req.TransactionID}
}

// exchange runs one message through the handler and returns the response it
// filled in. A nil response means the plugin dropped the packet.
func exchange(t *testing.T, h handler.Handler6, req *dhcpv6.Message) (*dhcpv6.Message, bool) {
	t.Helper()
	got, stop := h(req, newResponse(req))
	if got == nil {
		return nil, stop
	}
	msg, ok := got.(*dhcpv6.Message)
	require.True(t, ok, "the plugin must hand back the response it was given")
	return msg, stop
}

// ianaIn returns the answer for one IAID, or nil when the response carries
// none.
func ianaIn(msg *dhcpv6.Message, iaid [4]byte) *dhcpv6.OptIANA {
	for _, ia := range msg.Options.IANA() {
		if ia.IaId == iaid {
			return ia
		}
	}
	return nil
}

// leasedAddress returns the single address answered for one IAID, failing the
// test when the IA_NA is missing or carries a status instead.
func leasedAddress(t *testing.T, msg *dhcpv6.Message, iaid [4]byte) net.IP {
	t.Helper()
	ia := ianaIn(msg, iaid)
	require.NotNil(t, ia, "expected an IA_NA for IAID %x", iaid)
	addrs := ia.Options.Addresses()
	require.Len(t, addrs, 1, "expected exactly one address, got %v", ia)
	return addrs[0].IPv6Addr
}

// assertStatus checks the status code of one answered IA_NA.
func assertStatus(t *testing.T, msg *dhcpv6.Message, iaid [4]byte, want dhcpIana.StatusCode) {
	t.Helper()
	ia := ianaIn(msg, iaid)
	require.NotNil(t, ia, "expected an IA_NA for IAID %x", iaid)
	status := ia.Options.Status()
	require.NotNil(t, status, "expected a status code in the IA_NA for IAID %x", iaid)
	assert.Equal(t, want, status.StatusCode)
	assert.Empty(t, ia.Options.Addresses(), "an IA_NA answering with a status carries no address")
}

// solicit runs one SOLICIT and returns the address the client was given.
func solicit(t *testing.T, h handler.Handler6, duid dhcpv6.DUID, iaid [4]byte) net.IP {
	t.Helper()
	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeSolicit, duid, newIANA(iaid)))
	require.NotNil(t, resp)
	assert.False(t, stop, "the chain has to continue so the option plugins still run")
	return leasedAddress(t, resp, iaid)
}

// inPool reports whether an address falls inside the pool the tests configure.
func inPool(ip net.IP) bool {
	v6 := ip.To16()
	return bytes.Compare(v6, net.ParseIP(poolFirst).To16()) >= 0 &&
		bytes.Compare(v6, net.ParseIP(poolLast).To16()) <= 0
}

func TestSetupArgumentValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"too few arguments", []string{"unused.db", poolFirst, poolLast}},
		{"empty file name", []string{"", poolFirst, poolLast, leaseTime}},
		{"database path with a query string", []string{"leases.db?mode=memory", poolFirst, poolLast, leaseTime}},
		{"database path with a fragment", []string{"leases.db#one", poolFirst, poolLast, leaseTime}},
		{"invalid first address", []string{"unused.db", "not-an-ip", poolLast, leaseTime}},
		{"invalid last address", []string{"unused.db", poolFirst, "not-an-ip", leaseTime}},
		{"IPv4 first address", []string{"unused.db", "10.0.0.1", poolLast, leaseTime}},
		{"IPv4 last address", []string{"unused.db", poolFirst, "10.0.0.1", leaseTime}},
		{"inverted range", []string{"unused.db", poolLast, poolFirst, leaseTime}},
		{"range wider than a /96", []string{"unused.db", "2001:db8::", "2001:db9::", leaseTime}},
		{"invalid lease duration", []string{"unused.db", poolFirst, poolLast, "soon"}},
		{"zero lease duration", []string{"unused.db", poolFirst, poolLast, "0s"}},
		{"negative lease duration", []string{"unused.db", poolFirst, poolLast, "-1h"}},
		{"unknown option", []string{"unused.db", poolFirst, poolLast, leaseTime, "reticulate:splines"}},
		{"option without a value", []string{"unused.db", poolFirst, poolLast, leaseTime, "sweep"}},
		{"duplicate option", []string{"unused.db", poolFirst, poolLast, leaseTime, "sweep:1m", "sweep:2m"}},
		{"malformed sweep interval", []string{"unused.db", poolFirst, poolLast, leaseTime, "sweep:soon"}},
		{"zero sweep interval", []string{"unused.db", poolFirst, poolLast, leaseTime, "sweep:0s"}},
		{"negative sweep interval", []string{"unused.db", poolFirst, poolLast, leaseTime, "sweep:-1m"}},
		{"malformed decline probation", []string{"unused.db", poolFirst, poolLast, leaseTime, "decline-probation:later"}},
		{"negative decline probation", []string{"unused.db", poolFirst, poolLast, leaseTime, "decline-probation:-1h"}},
		{"malformed decline maximum", []string{"unused.db", poolFirst, poolLast, leaseTime, "decline-max:lots"}},
		{"negative decline maximum", []string{"unused.db", poolFirst, poolLast, leaseTime, "decline-max:-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := range6.Plugin.Setup6(tc.args...)
			assert.Error(t, err)
		})
	}
}

// TestSetupAcceptsOptionsInAnyOrder pins that the optional arguments are
// named rather than positional.
func TestSetupAcceptsOptionsInAnyOrder(t *testing.T) {
	cases := [][]string{
		{},
		{"sweep:90s"},
		{"decline-probation:1h"},
		{"decline-max:4"},
		{"decline-max:0", "decline-probation:0s", "sweep:90s"},
		{"decline-probation:1h", "sweep:90s", "decline-max:4"},
		{"sweep:90s", "decline-max:4", "decline-probation:1h"},
	}
	for _, extra := range cases {
		t.Run(strings(extra), func(t *testing.T) {
			args := append([]string{filepath.Join(t.TempDir(), "leases6.sqlite3"), poolFirst, poolLast, leaseTime}, extra...)
			h, err := range6.Plugin.Setup6(args...)
			require.NoError(t, err)
			assert.NotNil(t, h)
		})
	}
}

// strings names a subtest after the arguments it passes.
func strings(args []string) string {
	if len(args) == 0 {
		return "no options"
	}
	name := ""
	for i, a := range args {
		if i > 0 {
			name += " "
		}
		name += a
	}
	return name
}

func TestSolicitAllocatesAnAddress(t *testing.T) {
	h := setupPlugin(t)

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeSolicit, testDUID(1), newIANA(iaid1)))
	require.NotNil(t, resp)
	assert.False(t, stop)

	ia := ianaIn(resp, iaid1)
	require.NotNil(t, ia)
	// RFC 8415 §21.4: renew halfway through the lifetime, rebind at 80% of it.
	assert.Equal(t, 6*time.Hour, ia.T1)
	assert.Equal(t, 9*time.Hour+36*time.Minute, ia.T2)

	addrs := ia.Options.Addresses()
	require.Len(t, addrs, 1)
	assert.True(t, inPool(addrs[0].IPv6Addr), "got %s, which is outside the pool", addrs[0].IPv6Addr)
	assert.Equal(t, 12*time.Hour, addrs[0].PreferredLifetime)
	assert.Equal(t, 12*time.Hour, addrs[0].ValidLifetime)
}

// TestSolicitWithRapidCommitFillsTheReply drives the path the server takes
// when the client asked for a two-message exchange: the response is already a
// Reply rather than an Advertise, and the plugin fills it in the same way.
func TestSolicitWithRapidCommitFillsTheReply(t *testing.T) {
	h := setupPlugin(t)

	req := newRequest(t, dhcpv6.MessageTypeSolicit, testDUID(1), newIANA(iaid1))
	dhcpv6.WithRapidCommit(req)
	resp, err := dhcpv6.NewReplyFromMessage(req)
	require.NoError(t, err)

	got, stop := h(req, resp)
	require.NotNil(t, got)
	assert.False(t, stop)

	reply, ok := got.(*dhcpv6.Message)
	require.True(t, ok)
	assert.Equal(t, dhcpv6.MessageTypeReply, reply.MessageType)
	assert.True(t, inPool(leasedAddress(t, reply, iaid1)))
}

// TestRequestKeepsTheSolicitedAddress pins that a SOLICIT binding counts: the
// address a client was offered is the one it gets when it asks for it.
func TestRequestKeepsTheSolicitedAddress(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)

	offered := solicit(t, h, duid, iaid1)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, duid, newIANA(iaid1, offered)))
	require.NotNil(t, resp)
	assert.Equal(t, offered.String(), leasedAddress(t, resp, iaid1).String())
}

// TestClientHintIsHonoured pins that a client asking for a free address in the
// pool gets that one.
func TestClientHintIsHonoured(t *testing.T) {
	h := setupPlugin(t)
	wanted := net.ParseIP("2001:db8:1::1f0")

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, testDUID(1), newIANA(iaid1, wanted)))
	require.NotNil(t, resp)
	assert.Equal(t, wanted.String(), leasedAddress(t, resp, iaid1).String())
}

func TestRenewExtendsTheBinding(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Equal(t, held.String(), leasedAddress(t, resp, iaid1).String())
}

// TestRenewWithoutABindingGetsNoBinding is RFC 8415 §18.3.4: the client has to
// be told to start over rather than left waiting.
func TestRenewWithoutABindingGetsNoBinding(t *testing.T) {
	h := setupPlugin(t)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, testDUID(9),
		newIANA(iaid1, net.ParseIP("2001:db8:1::150"))))
	require.NotNil(t, resp)
	assertStatus(t, resp, iaid1, dhcpIana.StatusNoBinding)
}

func TestRebindExtendsTheBinding(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRebind, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assert.Equal(t, held.String(), leasedAddress(t, resp, iaid1).String())
}

// TestRebindWithoutABindingStaysQuiet is RFC 8415 §18.3.5: a REBIND reaches
// every server on the link, so one that knows nothing about the client says
// nothing and leaves the answer to the server that does.
func TestRebindWithoutABindingStaysQuiet(t *testing.T) {
	h := setupPlugin(t)

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRebind, testDUID(9),
		newIANA(iaid1, net.ParseIP("2001:db8:1::150"))))
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Empty(t, resp.Options.IANA(), "a REBIND we cannot answer gets no IA_NA at all")
}

func TestConfirm(t *testing.T) {
	cases := []struct {
		name       string
		addresses  []net.IP
		wantStatus *dhcpIana.StatusCode
	}{
		{"address from the pool", []net.IP{net.ParseIP("2001:db8:1::150")}, status(dhcpIana.StatusSuccess)},
		{"first address of the pool", []net.IP{net.ParseIP(poolFirst)}, status(dhcpIana.StatusSuccess)},
		{"last address of the pool", []net.IP{net.ParseIP(poolLast)}, status(dhcpIana.StatusSuccess)},
		{"address below the pool", []net.IP{net.ParseIP("2001:db8:1::ff")}, status(dhcpIana.StatusNotOnLink)},
		{"address above the pool", []net.IP{net.ParseIP("2001:db8:1::200")}, status(dhcpIana.StatusNotOnLink)},
		{"address from another link", []net.IP{net.ParseIP("2001:db8:2::150")}, status(dhcpIana.StatusNotOnLink)},
		{"one of two is off link", []net.IP{net.ParseIP("2001:db8:1::150"), net.ParseIP("2001:db8:2::1")}, status(dhcpIana.StatusNotOnLink)},
		{"no address at all", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := setupPlugin(t)
			resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeConfirm, testDUID(1), newIANA(iaid1, tc.addresses...)))
			require.NotNil(t, resp)
			assert.False(t, stop)
			assert.Empty(t, resp.Options.IANA(), "a CONFIRM is answered at the message level, not per IA")

			got := resp.Options.Status()
			if tc.wantStatus == nil {
				assert.Nil(t, got, "RFC 8415 §18.3.3 has no reply for a CONFIRM without addresses")
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.wantStatus, got.StatusCode)
		})
	}
}

func status(c dhcpIana.StatusCode) *dhcpIana.StatusCode { return &c }

// TestConfirmChangesNoBinding pins that a CONFIRM neither allocates nor frees:
// the client keeps whatever it had, and the pool is untouched.
func TestConfirmChangesNoBinding(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	_, _ = exchange(t, h, newRequest(t, dhcpv6.MessageTypeConfirm, duid, newIANA(iaid1, held)))

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assert.Equal(t, held.String(), leasedAddress(t, resp, iaid1).String())
}

func TestReleaseFreesTheAddress(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRelease, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assert.False(t, stop)
	assertStatus(t, resp, iaid1, dhcpIana.StatusSuccess)
	require.NotNil(t, resp.Options.Status())
	assert.Equal(t, dhcpIana.StatusSuccess, resp.Options.Status().StatusCode)

	// The binding is gone: a RENEW for it now has nothing to extend.
	renewed, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, duid, newIANA(iaid1, held)))
	require.NotNil(t, renewed)
	assertStatus(t, renewed, iaid1, dhcpIana.StatusNoBinding)

	// And the address is back in the pool: the next client can have it.
	other, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, testDUID(2), newIANA(iaid1, held)))
	require.NotNil(t, other)
	assert.Equal(t, held.String(), leasedAddress(t, other, iaid1).String())
}

// TestReleaseOfSomethingElse pins that a RELEASE only frees what the sender
// actually holds. Going by the DUID alone, or by the IAID alone, would let
// anyone who can forge one empty the pool.
func TestReleaseOfSomethingElse(t *testing.T) {
	cases := []struct {
		name    string
		iaid    [4]byte
		address func(held net.IP) net.IP
	}{
		{"an IAID with no binding", iaid2, func(held net.IP) net.IP { return held }},
		{"an address the client does not hold", iaid1, func(net.IP) net.IP { return net.ParseIP("2001:db8:1::1fe") }},
		{"no address at all", iaid1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := setupPlugin(t)
			duid := testDUID(1)
			held := solicit(t, h, duid, iaid1)

			var addrs []net.IP
			if tc.address != nil {
				addrs = []net.IP{tc.address(held)}
			}
			resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRelease, duid, newIANA(tc.iaid, addrs...)))
			require.NotNil(t, resp)
			assertStatus(t, resp, tc.iaid, dhcpIana.StatusNoBinding)

			renewed, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, duid, newIANA(iaid1, held)))
			require.NotNil(t, renewed)
			assert.Equal(t, held.String(), leasedAddress(t, renewed, iaid1).String(),
				"the client's own binding must survive")
		})
	}
}

// TestDeclineHoldsTheAddressBack pins the quarantine: the client reported the
// address as already in use, so the next client must not be walked into the
// same conflict.
func TestDeclineHoldsTheAddressBack(t *testing.T) {
	h := setupPool(t, "2001:db8:1::101")
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeDecline, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assert.False(t, stop)
	assertStatus(t, resp, iaid1, dhcpIana.StatusSuccess)
	require.NotNil(t, resp.Options.Status())
	assert.Equal(t, dhcpIana.StatusSuccess, resp.Options.Status().StatusCode)

	// A second client asking for exactly that address gets the other one.
	other := solicit(t, h, testDUID(2), iaid1)
	assert.NotEqual(t, held.String(), other.String(), "a declined address must stay out of the pool")
}

// TestDeclineWithoutProbationReturnsTheAddress pins that the quarantine can be
// turned off, which is what an operator who trusts their link wants.
func TestDeclineWithoutProbationReturnsTheAddress(t *testing.T) {
	h := setupPool(t, "2001:db8:1::100", "decline-probation:0s")
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeDecline, duid, newIANA(iaid1, held)))
	require.NotNil(t, resp)
	assertStatus(t, resp, iaid1, dhcpIana.StatusSuccess)

	other := solicit(t, h, testDUID(2), iaid1)
	assert.Equal(t, held.String(), other.String(), "with no probation the address goes straight back")
}

// TestDeclineOfSomethingElse mirrors TestReleaseOfSomethingElse: a DECLINE
// must not take an address the sender does not hold out of the pool.
func TestDeclineOfSomethingElse(t *testing.T) {
	h := setupPlugin(t)
	duid := testDUID(1)
	held := solicit(t, h, duid, iaid1)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeDecline, duid,
		newIANA(iaid1, net.ParseIP("2001:db8:1::1fe"))))
	require.NotNil(t, resp)
	assertStatus(t, resp, iaid1, dhcpIana.StatusNoBinding)

	renewed, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRenew, duid, newIANA(iaid1, held)))
	require.NotNil(t, renewed)
	assert.Equal(t, held.String(), leasedAddress(t, renewed, iaid1).String())
}

// TestQuarantineIsBounded pins decline-max: a client that declines everything
// it is offered cannot take the pool with it.
func TestQuarantineIsBounded(t *testing.T) {
	h := setupPool(t, "2001:db8:1::103", "decline-max:1")
	duid := testDUID(1)

	var declined []string
	for i := range 4 {
		held := solicit(t, h, duid, [4]byte{0, 0, 0, byte(i)})
		declined = append(declined, held.String())
		resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeDecline, duid, newIANA([4]byte{0, 0, 0, byte(i)}, held)))
		require.NotNil(t, resp)
		assertStatus(t, resp, [4]byte{0, 0, 0, byte(i)}, dhcpIana.StatusSuccess)
	}

	// Only one address may still be held back, so the pool is not empty.
	got := solicit(t, h, testDUID(2), iaid1)
	assert.Contains(t, declined, got.String(), "an evicted address has to be usable again")
}

func TestInformationRequestPassesThrough(t *testing.T) {
	h := setupPlugin(t)

	req := newRequest(t, dhcpv6.MessageTypeInformationRequest, testDUID(1), newIANA(iaid1))
	resp, stop := exchange(t, h, req)
	require.NotNil(t, resp)
	assert.False(t, stop)
	assert.Empty(t, resp.Options.Options, "an INFORMATION-REQUEST asks for configuration, not an address")
}

// TestUnhandledMessageTypesPassThrough pins that the plugin only acts on the
// message types RFC 8415 §18.3 gives it something to do for.
func TestUnhandledMessageTypesPassThrough(t *testing.T) {
	for _, mtype := range []dhcpv6.MessageType{
		dhcpv6.MessageTypeAdvertise,
		dhcpv6.MessageTypeReply,
		dhcpv6.MessageTypeReconfigure,
	} {
		t.Run(mtype.String(), func(t *testing.T) {
			h := setupPlugin(t)
			resp, stop := exchange(t, h, newRequest(t, mtype, testDUID(1), newIANA(iaid1)))
			require.NotNil(t, resp)
			assert.False(t, stop)
			assert.Empty(t, resp.Options.Options)
		})
	}
}

func TestTwoIANAsGetTwoAddresses(t *testing.T) {
	h := setupPlugin(t)

	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, testDUID(1), newIANA(iaid1), newIANA(iaid2)))
	require.NotNil(t, resp)
	require.Len(t, resp.Options.IANA(), 2)

	first, second := leasedAddress(t, resp, iaid1), leasedAddress(t, resp, iaid2)
	assert.NotEqual(t, first.String(), second.String(), "each IA_NA is its own binding")
	assert.True(t, inPool(first))
	assert.True(t, inPool(second))
}

// TestIANAsPerMessageAreCapped pins the bound on how much work one packet may
// ask for. Nine IA_NAs go in, eight are answered.
func TestIANAsPerMessageAreCapped(t *testing.T) {
	h := setupPlugin(t)

	var ianas []*dhcpv6.OptIANA
	for i := range 9 {
		ianas = append(ianas, newIANA([4]byte{0, 0, 0, byte(i)}))
	}
	resp, _ := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, testDUID(1), ianas...))
	require.NotNil(t, resp)
	assert.Len(t, resp.Options.IANA(), 8)
	assert.Nil(t, ianaIn(resp, [4]byte{0, 0, 0, 8}), "the ninth IA_NA is ignored")
}

func TestMalformedRequestsAreDropped(t *testing.T) {
	h := setupPlugin(t)

	t.Run("no client ID", func(t *testing.T) {
		req, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRequest
		req.AddOption(newIANA(iaid1))

		resp, stop := exchange(t, h, req)
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("client DUID over the RFC 8415 limit", func(t *testing.T) {
		// 129 octets of data plus the two-octet type code is 131, one past
		// the 130 the plugin accepts.
		duid := &dhcpv6.DUIDOpaque{Type: 65535, Data: make([]byte, 129)}
		resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, duid, newIANA(iaid1)))
		assert.Nil(t, resp)
		assert.True(t, stop)
	})

	t.Run("client DUID at the limit is served", func(t *testing.T) {
		duid := &dhcpv6.DUIDOpaque{Type: 65535, Data: make([]byte, 128)}
		resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, duid, newIANA(iaid1)))
		require.NotNil(t, resp)
		assert.False(t, stop)
		assert.True(t, inPool(leasedAddress(t, resp, iaid1)))
	})

	t.Run("relay message with nothing inside", func(t *testing.T) {
		got, stop := h(&dhcpv6.RelayMessage{}, &dhcpv6.Message{})
		assert.Nil(t, got)
		assert.True(t, stop)
	})
}

func TestPoolExhaustion(t *testing.T) {
	h := setupPool(t, "2001:db8:1::100")

	assert.Equal(t, "2001:db8:1::100", solicit(t, h, testDUID(1), iaid1).String())

	resp, stop := exchange(t, h, newRequest(t, dhcpv6.MessageTypeRequest, testDUID(2), newIANA(iaid1)))
	require.NotNil(t, resp)
	assert.False(t, stop, "an exhausted pool still lets the rest of the chain run")
	assertStatus(t, resp, iaid1, dhcpIana.StatusNoAddrsAvail)
}

// TestBindingsSurviveARestart runs setup twice over the same file: the second
// instance has to load the stored bindings and put them back in the allocator,
// so the client keeps its address and nobody else is handed it.
func TestBindingsSurviveARestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	duid := testDUID(1)

	first := setupPoolAt(t, dbPath, "2001:db8:1::101")
	held := solicit(t, first, duid, iaid1)

	second := setupPoolAt(t, dbPath, "2001:db8:1::101")
	assert.Equal(t, held.String(), solicit(t, second, duid, iaid1).String())
	assert.NotEqual(t, held.String(), solicit(t, second, testDUID(2), iaid1).String(),
		"a restored binding must still hold its address in the allocator")
}

// TestStoredHostnameIsSanitised reads the row back out of sqlite: the name
// comes off the wire, so what lands in the database is filtered and bounded.
func TestStoredHostnameIsSanitised(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	h := setupPoolAt(t, dbPath, poolLast)

	req := newRequest(t, dhcpv6.MessageTypeRequest, testDUID(1), newIANA(iaid1))
	dhcpv6.WithFQDN(0, "lap top;drop\x00.example")(req)
	resp, _ := exchange(t, h, req)
	require.NotNil(t, resp)

	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var hostname, ip string
	require.NoError(t, db.QueryRow("select ip, hostname from leases6").Scan(&ip, &hostname))
	assert.Equal(t, leasedAddress(t, resp, iaid1).String(), ip)
	assert.Equal(t, "laptopdrop.example", hostname)
}

// seedDB writes rows straight into the lease table, bypassing every check the
// plugin makes, to set up the states setup has to survive on reload.
func seedDB(t *testing.T, path string, rows [][5]any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	_, err = db.Exec("create table if not exists leases6 (duid blob, iaid int, ip text, expiry int, hostname text, primary key (duid, iaid))")
	require.NoError(t, err)
	for _, r := range rows {
		_, err := db.Exec("insert into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)", r[0], r[1], r[2], r[3], r[4])
		require.NoError(t, err)
	}
}

func TestSetupRejectsUnusableStoredRows(t *testing.T) {
	duid := testDUID(1).ToBytes()
	cases := []struct {
		name string
		row  [5]any
	}{
		{"empty DUID", [5]any{[]byte{}, 1, "2001:db8:1::110", 0, ""}},
		{"DUID over the limit", [5]any{make([]byte, 131), 1, "2001:db8:1::110", 0, ""}},
		{"negative IAID", [5]any{duid, -1, "2001:db8:1::110", 0, ""}},
		{"IAID past 32 bits", [5]any{duid, int64(1) << 33, "2001:db8:1::110", 0, ""}},
		{"malformed address", [5]any{duid, 1, "not-an-ip", 0, ""}},
		{"IPv4 address", [5]any{duid, 1, "10.0.0.1", 0, ""}},
		{"address outside the pool", [5]any{duid, 1, "2001:db8:9::1", 0, ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
			seedDB(t, dbPath, [][5]any{tc.row})

			_, err := range6.Plugin.Setup6(dbPath, poolFirst, poolLast, leaseTime)
			assert.Error(t, err)
		})
	}
}

// TestSetupRestoresAStoredBinding is the happy path of the same reload: a row
// written before the server started is served back to its owner.
func TestSetupRestoresAStoredBinding(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	duid := testDUID(1)
	seedDB(t, dbPath, [][5]any{
		{duid.ToBytes(), 1, "2001:db8:1::110", time.Now().Add(time.Hour).Unix(), "stored"},
	})

	h := setupPoolAt(t, dbPath, poolLast)
	assert.Equal(t, "2001:db8:1::110", solicit(t, h, duid, iaid1).String())
}
