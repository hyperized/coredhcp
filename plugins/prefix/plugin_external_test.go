// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/prefix"
)

func testDUID() dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
}

// solicitWith runs one SOLICIT, carrying a single IA_PD (IAID 1,2,3,4) with
// the given prefix hints, through an already set-up handler. Reusing the same
// handler across calls lets scenarios exercise several sequential exchanges
// against the same pool/lease state.
func solicitWith(t *testing.T, handle func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool), duid dhcpv6.DUID, hints ...*dhcpv6.OptIAPrefix) *dhcpv6.Message {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, hints...))
	require.NoError(t, err)

	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	result, _ := handle(req, resp)
	return result.(*dhcpv6.Message)
}

// solicitManyIAPDs runs one SOLICIT carrying n distinct IA_PDs, one per IAID
// from 1 to n, none of them hinting at a particular prefix. It exists for the
// per-message and per-client cap scenarios: solicitWith's single fixed IAID
// cannot carry more than one IA_PD in a message.
func solicitManyIAPDs(t *testing.T, handle func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool), duid dhcpv6.DUID, n int) *dhcpv6.Message {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	for i := 1; i <= n; i++ {
		req.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, byte(i)}})
	}

	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	result, _ := handle(req, resp)
	return result.(*dhcpv6.Message)
}

// releaseManyIAPDs runs one RELEASE carrying n distinct, empty IA_PDs, one per
// IAID from 1 to n. It exists for the per-message cap scenario on the release
// path: releaseWith answers a single IA_PD, and this needs many in one
// message.
func releaseManyIAPDs(t *testing.T, handle func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool), duid dhcpv6.DUID, n int) *dhcpv6.Message {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid))
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRelease
	for i := 1; i <= n; i++ {
		req.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, byte(i)}})
	}

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	result, _ := handle(req, resp)
	return result.(*dhcpv6.Message)
}

// duidOfLength returns a client DUID whose wire form (ToBytes) is exactly n
// octets. DUIDOpaque serialises as a 2-octet type code followed by Data
// verbatim, so Data needs n-2 octets; the arithmetic is verified here rather
// than assumed, since the wire encoding is not this package's to guarantee.
func duidOfLength(t *testing.T, n int) dhcpv6.DUID {
	t.Helper()

	d := &dhcpv6.DUIDOpaque{Type: dhcpv6.DUID_LL, Data: make([]byte, n-2)}
	require.Len(t, d.ToBytes(), n, "test setup: wire form must be exactly the requested length")
	return d
}

func TestRoundTrip(t *testing.T) {
	reqIAID := [4]uint8{0x12, 0x34, 0x56, 0x78}

	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}))
	req.AddOption(&dhcpv6.OptIAPD{
		IaId: reqIAID,
		T1:   0,
		T2:   0,
	})

	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	handler, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	result, final := handler(req, resp)
	if final {
		t.Log("Handler declared final")
	}
	t.Logf("%#v", result)

	// Sanity checks on the response
	success := result.GetOption(dhcpv6.OptionStatusCode)
	var mo dhcpv6.MessageOptions
	// No StatusCode option at all is an implicit success.
	if len(success) > 1 {
		t.Fatal("Got multiple StatusCode options")
	} else if len(success) == 1 {
		require.NoError(t, mo.FromBytes(success[0].ToBytes()))
		require.Equal(t, dhcpIana.StatusSuccess, mo.Status().StatusCode)
	}

	iapds := result.(*dhcpv6.Message).Options.IAPD()
	require.Len(t, iapds, 1, "expected exactly 1 IAPD")
	iapd := iapds[0]
	assert.Equal(t, reqIAID, iapd.IaId)

	if status := result.(*dhcpv6.Message).Options.Status(); status != nil {
		assert.Equal(t, dhcpIana.StatusSuccess, status.StatusCode)
	}

	assert.Len(t, iapd.Options.Prefixes(), 1, "response should contain exactly one prefix in the IA_PD option")
}

func TestSetupPrefixArgValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no args", nil, "need both a subnet and an allocation max size"},
		{"one arg", []string{"2001:db8::/48"}, "need both a subnet and an allocation max size"},
		{"invalid CIDR", []string{"not-a-cidr", "64"}, "invalid pool subnet"},
		{"non-numeric alloc size", []string{"2001:db8::/48", "abc"}, "invalid prefix length"},
		{"alloc size above 128", []string{"2001:db8::/48", "200"}, "invalid prefix length"},
		{"alloc size negative", []string{"2001:db8::/48", "-1"}, "invalid prefix length"},
		{"alloc size smaller than pool", []string{"2001:db8::/48", "40"}, "could not initialize prefix allocator"},
		{"malformed lease duration", []string{"2001:db8::/48", "64", "forever"}, "invalid lease duration"},
		{"zero lease duration", []string{"2001:db8::/48", "64", "0s"}, "lease duration has to be positive"},
		{"negative lease duration", []string{"2001:db8::/48", "64", "-1h"}, "lease duration has to be positive"},
		{"unknown trailing argument", []string{"2001:db8::/48", "64", "1h", "reap:5m"}, "unexpected argument"},
		{"duplicate sweep argument", []string{"2001:db8::/48", "64", "1h", "sweep:5m", "sweep:6m"}, "argument sweep given more than once"},
		{"malformed sweep interval", []string{"2001:db8::/48", "64", "1h", "sweep:soon"}, "invalid sweep interval"},
		{"zero sweep interval", []string{"2001:db8::/48", "64", "1h", "sweep:0s"}, "sweep interval has to be positive"},
		{"ipv4 pool subnet", []string{"192.0.2.0/24", "24"}, "not IPv6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := prefix.Plugin.Setup6(tt.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestHandleMalformedRelayMessage(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	// A RelayMessage with no embedded OptionRelayMsg makes GetInnerMessage fail.
	req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	result, final := h(req, resp)
	assert.Nil(t, result)
	assert.True(t, final)
}

func TestHandleMissingClientID(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	// A SOLICIT with an IA_PD but no Client ID option.
	req, err := dhcpv6.NewMessage(dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}))
	require.NoError(t, err)
	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	result, final := h(req, resp)
	assert.Nil(t, result)
	assert.True(t, final)
}

func TestHandlePrefixNilOptionDefaultsToEmptyHint(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{1, 2, 3, 4}}
	// A hint option with no Prefix at all (as opposed to an empty *net.IPNet{}).
	iapd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: nil})

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(testDUID()))
	require.NoError(t, err)
	req.AddOption(iapd)

	resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
	require.NoError(t, err)

	result, _ := h(req, resp)
	msg := result.(*dhcpv6.Message)
	iapds := msg.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Len(t, iapds[0].Options.Prefixes(), 1)
}

func TestHandleMultiHintRegression(t *testing.T) {
	// Regression test for 7f79c14: a single SOLICIT carrying two hints that
	// both require a fresh allocation must record (and return) two distinct
	// leases. The bug kept only the last one allocated.
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	_, hint1, err := net.ParseCIDR("2001:db8:0:1::/64")
	require.NoError(t, err)
	_, hint2, err := net.ParseCIDR("2001:db8:0:2::/64")
	require.NoError(t, err)

	resp := solicitWith(t, h, testDUID(),
		&dhcpv6.OptIAPrefix{Prefix: hint1},
		&dhcpv6.OptIAPrefix{Prefix: hint2},
	)

	iapds := resp.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Len(t, iapds[0].Options.Prefixes(), 2, "both hints should have produced a lease")

	// A second SOLICIT re-requesting the exact same two prefixes must renew
	// both as exact matches, proving both survived in the recorded lease set.
	resp2 := solicitWith(t, h, testDUID(),
		&dhcpv6.OptIAPrefix{Prefix: hint1},
		&dhcpv6.OptIAPrefix{Prefix: hint2},
	)
	iapds2 := resp2.Options.IAPD()
	require.Len(t, iapds2, 1)
	assert.Len(t, iapds2[0].Options.Prefixes(), 2, "both previously allocated leases should still be known")
}

func TestHandleAllocatorExhaustionMidRequest(t *testing.T) {
	// A pool exactly the size of one allocation: two distinct hints in the
	// same request means the second Allocate() call must fail.
	h, err := prefix.Plugin.Setup6("2001:db8::/64", "64")
	require.NoError(t, err)

	_, hint1, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)
	_, hint2, err := net.ParseCIDR("2001:db9::/64")
	require.NoError(t, err)

	resp := solicitWith(t, h, testDUID(),
		&dhcpv6.OptIAPrefix{Prefix: hint1},
		&dhcpv6.OptIAPrefix{Prefix: hint2},
	)

	iapds := resp.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Len(t, iapds[0].Options.Prefixes(), 1, "only one of the two hints could be satisfied")
}

func TestHandleEmptyResponseWhenPoolExhausted(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/64", "64")
	require.NoError(t, err)

	// First client takes the only available prefix.
	first := solicitWith(t, h, testDUID())
	require.Len(t, first.Options.IAPD()[0].Options.Prefixes(), 1)

	// A second, distinct client has no known leases and the pool is exhausted:
	// the response must carry StatusNoPrefixAvail and no IAPrefix options.
	secondDUID := &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	}
	second := solicitWith(t, h, secondDUID)
	iapds := second.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Empty(t, iapds[0].Options.Prefixes())
	status := iapds[0].Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusNoPrefixAvail, status.StatusCode)
}

func TestHandleRenewsExactHintMatch(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	first := solicitWith(t, h, testDUID())
	firstPrefixes := first.Options.IAPD()[0].Options.Prefixes()
	require.Len(t, firstPrefixes, 1)
	leased := firstPrefixes[0].Prefix

	// Re-request the exact same prefix as an explicit hint: it must be
	// recognised as an exact match and renewed, not re-allocated.
	second := solicitWith(t, h, testDUID(), &dhcpv6.OptIAPrefix{Prefix: leased})
	secondPrefixes := second.Options.IAPD()[0].Options.Prefixes()
	require.Len(t, secondPrefixes, 1)
	assert.True(t, leased.IP.Equal(secondPrefixes[0].Prefix.IP))
}

func TestHandleGivesOutRemainingLeaseForZeroIPHint(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	first := solicitWith(t, h, testDUID())
	require.Len(t, first.Options.IAPD()[0].Options.Prefixes(), 1)

	// An explicit "any" hint (IP set to the zero address, no length) must
	// still be matched against the already-known lease.
	second := solicitWith(t, h, testDUID(), &dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IPv6zero}})
	secondPrefixes := second.Options.IAPD()[0].Options.Prefixes()
	require.Len(t, secondPrefixes, 1)
}

func TestHandleZeroIPHintLengthMismatchAllocatesNew(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	first := solicitWith(t, h, testDUID())
	require.Len(t, first.Options.IAPD()[0].Options.Prefixes(), 1)

	// An "any" hint that requests a length no known lease has (the pool only
	// ever hands out /64s) can't be satisfied by an existing lease, so a new
	// one must be allocated instead.
	second := solicitWith(t, h, testDUID(), &dhcpv6.OptIAPrefix{
		Prefix: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(70, 128)},
	})
	secondPrefixes := second.Options.IAPD()[0].Options.Prefixes()
	require.Len(t, secondPrefixes, 1, "a fresh /64 should have been allocated")

	// The client now has two distinct known leases. Two more length-only
	// "any" hints in one request: the give-out loop for a satisfied hint
	// never breaks out early, so the *first* hint's inner loop walks every
	// not-yet-given-out known lease and claims all of them (both existing
	// leases end up attached to hintIdx 0), exercising the "already given
	// out this exchange" skip (178-179) along the way. The second hint then
	// finds nothing left to give out and falls through to a fresh
	// allocation instead. This means a single unqualified hint can end up
	// absorbing more than one existing lease - a quirk of the current
	// no-break loop, pinned here rather than assumed away.
	third := solicitWith(t, h, testDUID(),
		&dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IPv6zero}},
		&dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IPv6zero}},
	)
	thirdPrefixes := third.Options.IAPD()[0].Options.Prefixes()
	require.Len(t, thirdPrefixes, 3, "both known leases plus one freshly allocated prefix")
}

// A client that already holds a lease and then sends an IA_PD hint whose
// prefix is absent on the wire (the decoder yields Prefix == nil for a zero
// prefix-length) used to crash the handler with a nil dereference in the
// lease-matching pass. It must behave like an absent hint instead.
func TestHandleNilHintPrefixWithExistingLease(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	duid := testDUID()

	// First exchange: acquire a lease so the matching passes have known
	// leases to walk.
	first := solicitWith(t, h, duid)
	require.NotEmpty(t, first.Options.IAPD()[0].Options.Prefixes())

	// Second exchange: same client, one nil-prefix hint.
	var second *dhcpv6.Message
	require.NotPanics(t, func() {
		second = solicitWith(t, h, duid, &dhcpv6.OptIAPrefix{Prefix: nil})
	})

	// The reply carries a usable prefix rather than a status failure.
	iapds := second.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.NotEmpty(t, iapds[0].Options.Prefixes())
}

// TestSetupPrefixOptionalArguments covers the argument shapes that must be
// accepted: the lease duration is positional and optional, and the sweep
// argument may appear with or without it.
func TestSetupPrefixOptionalArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"defaults", []string{"2001:db8::/48", "64"}},
		{"an explicit lease duration", []string{"2001:db8::/48", "64", "30m"}},
		{"a sweep argument with no lease duration", []string{"2001:db8::/48", "64", "sweep:45s"}},
		{"both", []string{"2001:db8::/48", "64", "30m", "sweep:45s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := prefix.Plugin.Setup6(tc.args...)
			require.NoError(t, err)
			assert.NotNil(t, h)
		})
	}
}

// releaseWith runs one RELEASE listing the given prefixes in a single IA_PD and
// returns the Reply the plugin filled in. The server builds the Reply and sends
// it whatever the chain returns, so the handler must hand it back rather than
// ending the chain.
func releaseWith(t *testing.T, handle func(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool), duid dhcpv6.DUID, iaid [4]byte, prefixes ...*dhcpv6.OptIAPrefix) *dhcpv6.Message {
	t.Helper()

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD(iaid, prefixes...))
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeRelease

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	result, stop := handle(req, resp)
	require.NotNil(t, result, "later plugins must still see the release")
	assert.False(t, stop)
	return result.(*dhcpv6.Message)
}

// iapdStatus reads the status code option of the IA_PD answering iaid.
func iapdStatus(t *testing.T, msg *dhcpv6.Message, iaid [4]byte) *dhcpv6.OptStatusCode {
	t.Helper()

	for _, iapd := range msg.Options.IAPD() {
		if iapd.IaId != iaid {
			continue
		}
		status := iapd.Options.Status()
		require.NotNil(t, status, "every released IA_PD must carry a status code")
		return status
	}
	t.Fatalf("no IA_PD in the reply for IAID %x", iaid)
	return nil
}

// TestHandleReleaseFreesAndAnswersSuccess covers RFC 8415 §18.3.7 for a
// binding the server holds: the prefix goes back to the pool, the IA_PD is
// answered with Success, and the Reply carries a message-level Success.
func TestHandleReleaseFreesAndAnswersSuccess(t *testing.T) {
	// A pool of exactly one prefix, so the release is the only thing that can
	// make the second allocation possible.
	h, err := prefix.Plugin.Setup6("2001:db8::/64", "64")
	require.NoError(t, err)

	duid := testDUID()
	iaid := [4]byte{1, 2, 3, 4}

	held := solicitWith(t, h, duid).Options.IAPD()[0].Options.Prefixes()
	require.Len(t, held, 1)

	reply := releaseWith(t, h, duid, iaid, held[0])
	assert.Equal(t, dhcpIana.StatusSuccess, iapdStatus(t, reply, iaid).StatusCode)

	status := reply.Options.Status()
	require.NotNil(t, status, "the Reply itself must carry a status code")
	assert.Equal(t, dhcpIana.StatusSuccess, status.StatusCode)

	// The prefix is genuinely back: a different client can take it.
	other := &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	}
	assert.Len(t, solicitWith(t, h, other).Options.IAPD()[0].Options.Prefixes(), 1)
}

// TestHandleReleaseAnswersNoBinding covers the IA_PDs the server holds nothing
// for. NoBinding is what tells the client to stop retrying, so every one of
// these shapes has to produce it rather than a bare Success. NoBinding also
// carries no message text: a sender can ask for it over and over just by
// releasing prefixes it never held, and RFC 8415 §21.13 leaves the text
// optional, so it must not become an amplification vector.
func TestHandleReleaseAnswersNoBinding(t *testing.T) {
	_, someoneElses, err := net.ParseCIDR("2001:db8:0:ffff::/64")
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		prefixes []*dhcpv6.OptIAPrefix
	}{
		{"an IA_PD listing no prefixes at all", nil},
		{"a prefix this client does not hold", []*dhcpv6.OptIAPrefix{{Prefix: someoneElses}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
			require.NoError(t, err)

			duid := testDUID()
			iaid := [4]byte{1, 2, 3, 4}
			require.Len(t, solicitWith(t, h, duid).Options.IAPD()[0].Options.Prefixes(), 1)

			reply := releaseWith(t, h, duid, iaid, tc.prefixes...)
			status := iapdStatus(t, reply, iaid)
			assert.Equal(t, dhcpIana.StatusNoBinding, status.StatusCode)
			assert.Empty(t, status.StatusMessage, "NoBinding must carry no message text")

			// The lease the client did not release must survive.
			assert.Len(t, solicitWith(t, h, duid).Options.IAPD()[0].Options.Prefixes(), 1)
		})
	}
}

// TestHandleDeclineIsIgnored covers RFC 8415 §18.3.8: DECLINE is about IA_NA
// and IA_TA addresses a client found in use on the link, so a delegating router
// answers with no IA_PD at all rather than renewing what the client holds.
func TestHandleDeclineIsIgnored(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	duid := testDUID()
	require.Len(t, solicitWith(t, h, duid).Options.IAPD()[0].Options.Prefixes(), 1)

	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duid), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}))
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeDecline

	resp, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	resp.MessageType = dhcpv6.MessageTypeReply

	result, stop := h(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Empty(t, result.(*dhcpv6.Message).Options.IAPD(), "a decline is not about prefixes")
}

// TestHandleCapsIAPDsAnsweredPerMessage pins the per-message IA_PD cap: a
// SOLICIT carrying more IA_PDs than the plugin will answer for gets back at
// most 8 IA_PD options, not one for every IA_PD it sent. The per-client cap
// is raised well out of the way so this exercises the per-message limit
// alone, not the pool or the per-client cap.
func TestHandleCapsIAPDsAnsweredPerMessage(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/60", "64", "1h", "max-prefixes:20")
	require.NoError(t, err)

	resp := solicitManyIAPDs(t, h, testDUID(), 12)
	assert.Len(t, resp.Options.IAPD(), 8, "the reply must not grow past the per-message cap")
}

// TestHandleReleaseCapsIAPDsAnsweredPerMessage is the RELEASE counterpart: the
// per-message cap sits ahead of both message types, so a RELEASE listing more
// IA_PDs than the cap allows is answered the same way.
func TestHandleReleaseCapsIAPDsAnsweredPerMessage(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
	require.NoError(t, err)

	resp := releaseManyIAPDs(t, h, testDUID(), 12)
	assert.Len(t, resp.Options.IAPD(), 8, "the reply must not grow past the per-message cap")
}

// TestHandleCapsNewAllocationsPerClient pins the per-client cap: with the
// default of four, a client asking for eight fresh prefixes in one message
// gets four of them and four NoPrefixAvail answers, not eight prefixes from a
// pool that had room for all of them.
func TestHandleCapsNewAllocationsPerClient(t *testing.T) {
	// A /61 carved into /64s holds exactly eight prefixes, so the pool itself
	// could serve every request; only the per-client cap should refuse any.
	h, err := prefix.Plugin.Setup6("2001:db8::/61", "64")
	require.NoError(t, err)

	resp := solicitManyIAPDs(t, h, testDUID(), 8)
	iapds := resp.Options.IAPD()
	require.Len(t, iapds, 8)

	var granted, refused int
	for _, iapd := range iapds {
		switch {
		case len(iapd.Options.Prefixes()) == 1:
			granted++
		case iapd.Options.Status() != nil && iapd.Options.Status().StatusCode == dhcpIana.StatusNoPrefixAvail:
			refused++
		}
	}
	assert.Equal(t, 4, granted, "exactly the default cap should be granted a prefix")
	assert.Equal(t, 4, refused, "the rest should be refused with NoPrefixAvail")
}

// TestHandleCapsNewAllocationsAcrossMessages pins that the per-client cap
// holds across separate exchanges, not just within one message: a client
// that already holds the default maximum is refused a further prefix in a
// later SOLICIT, while a different client is unaffected.
func TestHandleCapsNewAllocationsAcrossMessages(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/59", "64")
	require.NoError(t, err)

	duid := testDUID()
	first := solicitManyIAPDs(t, h, duid, 4)
	var held int
	for _, iapd := range first.Options.IAPD() {
		held += len(iapd.Options.Prefixes())
	}
	require.Equal(t, 4, held, "the client must hold the default maximum before the second exchange")

	// A hint naming a prefix the client does not hold cannot be satisfied by
	// renewal, so it must go through allocateForUnsatisfied and hit the cap.
	_, freshBlock, err := net.ParseCIDR("2001:db8:0:1f::/64")
	require.NoError(t, err)
	second := solicitWith(t, h, duid, &dhcpv6.OptIAPrefix{Prefix: freshBlock})
	iapds := second.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Empty(t, iapds[0].Options.Prefixes())
	status := iapds[0].Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusNoPrefixAvail, status.StatusCode)

	// A different client, same pool, is not affected by the first one's cap.
	other := &dhcpv6.DUIDLL{
		HWType:        dhcpIana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
	}
	assert.Len(t, solicitWith(t, h, other).Options.IAPD()[0].Options.Prefixes(), 1)
}

// TestHandleRenewalIsNotCapped pins that renewing prefixes already held is not
// counted as a new allocation: a client at its maximum gets every one of them
// back when it re-hints at exactly what it holds, rather than NoPrefixAvail.
func TestHandleRenewalIsNotCapped(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/59", "64", "1h", "max-prefixes:4")
	require.NoError(t, err)

	duid := testDUID()
	first := solicitManyIAPDs(t, h, duid, 4)
	var held []*dhcpv6.OptIAPrefix
	for _, iapd := range first.Options.IAPD() {
		held = append(held, iapd.Options.Prefixes()...)
	}
	require.Len(t, held, 4)

	second := solicitWith(t, h, duid, held...)
	iapds := second.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Len(t, iapds[0].Options.Prefixes(), 4, "renewing all four held prefixes must not be refused")
}

// TestHandleMaxPrefixesOneIsHonoured pins that an explicit max-prefixes:1 is
// honoured end to end: the first prefix is granted, and a second is refused
// even though the pool still has room.
func TestHandleMaxPrefixesOneIsHonoured(t *testing.T) {
	h, err := prefix.Plugin.Setup6("2001:db8::/62", "64", "1h", "max-prefixes:1")
	require.NoError(t, err)

	duid := testDUID()
	first := solicitWith(t, h, duid)
	require.Len(t, first.Options.IAPD()[0].Options.Prefixes(), 1)

	_, freshBlock, err := net.ParseCIDR("2001:db8:0:1::/64")
	require.NoError(t, err)
	second := solicitWith(t, h, duid, &dhcpv6.OptIAPrefix{Prefix: freshBlock})
	iapds := second.Options.IAPD()
	require.Len(t, iapds, 1)
	assert.Empty(t, iapds[0].Options.Prefixes())
	status := iapds[0].Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusNoPrefixAvail, status.StatusCode)
}

// TestHandleDUIDLengthCap pins the client-DUID length cap: a DUID right at
// the RFC 8415 §11.1 boundary is served normally, and one octet over it is
// dropped before the message-type switch, for both a SOLICIT and a RELEASE.
func TestHandleDUIDLengthCap(t *testing.T) {
	// 130 mirrors the plugin's unexported maxDUIDLength: the 128 octets
	// RFC 8415 §11.1 allows plus the 2-octet DUID type code.
	const maxDUIDLength = 130

	t.Run("at the boundary is served normally", func(t *testing.T) {
		h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
		require.NoError(t, err)

		resp := solicitWith(t, h, duidOfLength(t, maxDUIDLength))
		iapds := resp.Options.IAPD()
		require.Len(t, iapds, 1)
		assert.Len(t, iapds[0].Options.Prefixes(), 1)
	})

	t.Run("one octet over is dropped for a SOLICIT", func(t *testing.T) {
		h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
		require.NoError(t, err)

		req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duidOfLength(t, maxDUIDLength+1)), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}))
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)

		result, final := h(req, resp)
		assert.Nil(t, result)
		assert.True(t, final)
	})

	t.Run("one octet over is dropped for a RELEASE", func(t *testing.T) {
		h, err := prefix.Plugin.Setup6("2001:db8::/48", "64")
		require.NoError(t, err)

		req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(duidOfLength(t, maxDUIDLength+1)), dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}))
		require.NoError(t, err)
		req.MessageType = dhcpv6.MessageTypeRelease

		resp, err := dhcpv6.NewMessage()
		require.NoError(t, err)
		resp.MessageType = dhcpv6.MessageTypeReply

		result, final := h(req, resp)
		assert.Nil(t, result)
		assert.True(t, final)
	})
}
