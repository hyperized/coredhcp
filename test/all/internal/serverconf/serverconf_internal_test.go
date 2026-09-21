// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverconf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringify(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want string
	}{
		{name: "nil is an argument-less plugin", in: nil, want: ""},
		{name: "a string passes through unchanged", in: "172.31.246.2", want: "172.31.246.2"},
		{name: "an integer is rendered like fmt does", in: 1400, want: "1400"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stringify(tc.in))
		})
	}
}

func TestSectionChain(t *testing.T) {
	t.Run("a nil section is not an error", func(t *testing.T) {
		var s *section
		got, err := s.chain(4)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("plugins with mixed argument types", func(t *testing.T) {
		s := &section{Plugins: []map[string]any{
			{"mtu": 1400},
			{"server_id": "172.31.246.2"},
			{"leasehook": nil},
		}}
		got, err := s.chain(4)
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, Plugin{Name: "mtu", Args: []string{"1400"}}, got[0])
		assert.Equal(t, Plugin{Name: "server_id", Args: []string{"172.31.246.2"}}, got[1])
		assert.Equal(t, "leasehook", got[2].Name)
		assert.Empty(t, got[2].Args, "a nil value is an argument-less plugin, not a missing one")
	})

	t.Run("an item with two plugin names is rejected", func(t *testing.T) {
		s := &section{Plugins: []map[string]any{
			{"metrics": "unix:/run/coredhcp/metrics.sock"},
			{"a": "1", "b": "2"},
		}}
		_, err := s.chain(6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server6 plugin #2 holds 2 names")
	})
}
