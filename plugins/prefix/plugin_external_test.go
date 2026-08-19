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
	// leases, not just the last one allocated.
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
