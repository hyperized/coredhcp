// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDup(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)

	dupPrefix := dup(prefix)
	assert.True(t, samePrefix(dupPrefix, prefix))
	// dup must be a deep copy: mutating the source must not affect the copy
	prefix.IP[0] = 0xff
	assert.False(t, dupPrefix.IP.Equal(prefix.IP))
}

func TestSamePrefix(t *testing.T) {
	_, a, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)
	_, b, err := net.ParseCIDR("2001:db8::/48")
	require.NoError(t, err)
	_, c, err := net.ParseCIDR("2001:db9::/48")
	require.NoError(t, err)

	tests := []struct {
		name string
		a, b *net.IPNet
		want bool
	}{
		{"both nil", nil, nil, false},
		{"a nil", nil, b, false},
		{"b nil", a, nil, false},
		{"equal prefixes", a, b, true},
		{"different prefixes", a, c, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, samePrefix(tt.a, tt.b))
		})
	}
}

func TestRecordKey(t *testing.T) {
	duid1 := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	duid2 := &dhcpv6.DUIDLL{HWType: dhcpIana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 6}}

	assert.Equal(t, recordKey(duid1), recordKey(duid1))
	assert.NotEqual(t, recordKey(duid1), recordKey(duid2))
}
