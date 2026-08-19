// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package macfilter

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeMACFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "macs.txt")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestSetupState(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantErr   string
		wantAllow bool
		wantMACs  int
	}{
		{
			name:    "no args",
			args:    nil,
			wantErr: "need a mode argument",
		},
		{
			name:    "invalid mode",
			args:    []string{"maybe", "aa:bb:cc:dd:ee:ff"},
			wantErr: "invalid mode",
		},
		{
			name:    "no MAC arguments",
			args:    []string{"allow"},
			wantErr: "need at least one MAC address",
		},
		{
			name:    "invalid MAC argument",
			args:    []string{"allow", "not-a-mac"},
			wantErr: "invalid MAC address",
		},
		{
			name:      "valid allow, single MAC",
			args:      []string{"allow", "aa:bb:cc:dd:ee:ff"},
			wantAllow: true,
			wantMACs:  1,
		},
		{
			name:      "valid deny, multiple MACs deduplicated",
			args:      []string{"deny", "aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"},
			wantAllow: false,
			wantMACs:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := setupState(tc.args...)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, p)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)
			assert.Equal(t, tc.wantAllow, p.allow)
			assert.Len(t, p.macs, tc.wantMACs)
		})
	}
}

func TestSetupStateFileSource(t *testing.T) {
	t.Run("valid file, comments and blank lines ignored", func(t *testing.T) {
		path := writeMACFile(t, "# allowed devices\n\naa:bb:cc:dd:ee:ff\n  # indented comment\nAA:BB:CC:DD:EE:00\n")
		p, err := setupState("allow", "file:"+path)
		require.NoError(t, err)
		assert.Len(t, p.macs, 2)
	})

	t.Run("file combined with a direct MAC argument", func(t *testing.T) {
		path := writeMACFile(t, "aa:bb:cc:dd:ee:ff\n")
		p, err := setupState("deny", "11:22:33:44:55:66", "file:"+path)
		require.NoError(t, err)
		assert.Len(t, p.macs, 2)
	})

	t.Run("empty file path", func(t *testing.T) {
		_, err := setupState("allow", "file:")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty file path")
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := setupState("allow", "file:"+filepath.Join(t.TempDir(), "missing.txt"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read")
	})

	t.Run("invalid MAC in file names the line", func(t *testing.T) {
		path := writeMACFile(t, "aa:bb:cc:dd:ee:ff\nnot-a-mac\n")
		_, err := setupState("allow", "file:"+path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ":2:")
		assert.Contains(t, err.Error(), "not-a-mac")
	})

	t.Run("file with only comments yields no MACs", func(t *testing.T) {
		path := writeMACFile(t, "# nothing here\n\n")
		_, err := setupState("allow", "file:"+path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "need at least one MAC address")
	})
}

func TestPluginStateDrop(t *testing.T) {
	listed := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	unlisted := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	cases := []struct {
		name string
		p    *pluginState
		mac  net.HardwareAddr
		want bool
	}{
		{"allow: listed MAC passes", &pluginState{allow: true, macs: map[string]struct{}{listed.String(): {}}}, listed, false},
		{"allow: unlisted MAC drops", &pluginState{allow: true, macs: map[string]struct{}{listed.String(): {}}}, unlisted, true},
		{"deny: listed MAC drops", &pluginState{allow: false, macs: map[string]struct{}{listed.String(): {}}}, listed, true},
		{"deny: unlisted MAC passes", &pluginState{allow: false, macs: map[string]struct{}{listed.String(): {}}}, unlisted, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.p.drop(tc.mac))
		})
	}
}

func TestPluginStateDropCaseInsensitive(t *testing.T) {
	p := &pluginState{allow: false, macs: map[string]struct{}{"aa:bb:cc:dd:ee:ff": {}}}
	assert.True(t, p.drop(net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}))
}
