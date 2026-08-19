// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package autoconfigure

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup4(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantVal dhcpv4.AutoConfiguration
		wantErr string
	}{
		{name: "no arguments defaults to 0", args: nil, wantVal: dhcpv4.AutoConfiguration(0)},
		{name: "0", args: []string{"0"}, wantVal: dhcpv4.AutoConfiguration(0)},
		{name: "1", args: []string{"1"}, wantVal: dhcpv4.AutoConfiguration(1)},
		{name: "DoNotAutoConfigure", args: []string{"DoNotAutoConfigure"}, wantVal: dhcpv4.DoNotAutoConfigure},
		{name: "AutoConfigure", args: []string{"AutoConfigure"}, wantVal: dhcpv4.AutoConfigure},
		{name: "unknown value", args: []string{"bogus"}, wantErr: "unexpected value 'bogus' for autoconfigure argument"},
		{name: "too many arguments", args: []string{"1", "extra"}, wantErr: "too many arguments"},
		{name: "unknown value takes precedence over too many arguments", args: []string{"bogus", "extra"}, wantErr: "unexpected value 'bogus' for autoconfigure argument"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := setup4(tc.args...)
			if tc.wantErr != "" {
				assert.Nil(t, h)
				if assert.Error(t, err) {
					assert.Equal(t, tc.wantErr, err.Error())
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, h)
		})
	}
}
