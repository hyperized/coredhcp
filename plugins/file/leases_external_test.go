// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/plugins/file"
)

// registeredSources returns every source setup registered under name, and
// drops them again when the test finishes so the next test does not see this
// instance. The server4 and server6 instances of this plugin reading one file
// share a name, so this returns a slice where the other plugins return one.
func registeredSources(t *testing.T, name string) []leases.Source {
	t.Helper()
	var found []leases.Source
	for _, s := range leases.Sources() {
		if s.Name() == name {
			t.Cleanup(func() { leases.Unregister(s) })
			found = append(found, s)
		}
	}
	return found
}

func TestSetup4RegistersStaticLeases(t *testing.T) {
	path := writeLeases(t, "00:11:22:33:44:55 192.0.2.100\n00:11:22:33:44:56 192.0.2.101\n")

	h, err := file.Plugin.Setup4(path)
	require.NoError(t, err)
	require.NotNil(t, h)

	sources := registeredSources(t, "file "+path)
	require.Len(t, sources, 1)
	src := sources[0]

	held := src.Leases()
	require.Len(t, held, 2)
	for _, l := range held {
		assert.Equal(t, uint8(4), l.Family)
		assert.True(t, l.Static)
		assert.True(t, l.Expires.IsZero())
		assert.Equal(t, "file "+path, l.Source)
		assert.Equal(t, 32, l.Address.Bits())
	}
	assert.Nil(t, src.Pools())
}

func TestSetup6RegistersStaticLeases(t *testing.T) {
	path := writeLeases(t, "00:11:22:33:44:55 2001:db8::10:1\n")

	h, err := file.Plugin.Setup6(path)
	require.NoError(t, err)
	require.NotNil(t, h)

	sources := registeredSources(t, "file "+path)
	require.Len(t, sources, 1)

	held := sources[0].Leases()
	require.Len(t, held, 1)
	assert.Equal(t, uint8(6), held[0].Family)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::10:1/128"), held[0].Address)
}

func TestBothFamiliesRegisterSeparately(t *testing.T) {
	path := writeLeases(t, "00:11:22:33:44:55 2001:db8::10:1\n")

	_, err := file.Plugin.Setup6(path)
	require.NoError(t, err)
	_, err = file.Plugin.Setup6(path)
	require.NoError(t, err)

	// Two instances of the plugin on one file are two sources. They report
	// the same name, which is why a reader filtering by source has to expect
	// more than one.
	assert.Len(t, registeredSources(t, "file "+path), 2)
}

func TestSetupFailureRegistersNothing(t *testing.T) {
	path := writeLeases(t, "not a lease\n")

	_, err := file.Plugin.Setup4(path)
	require.Error(t, err)

	assert.Empty(t, registeredSources(t, "file "+path))
}
