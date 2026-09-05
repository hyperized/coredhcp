// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package relayinfo

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		want    pluginArgs
		wantErr error
		errText string
	}{
		{
			name: "file and key",
			args: []string{"file:/etc/ports.txt", "key:circuit-id"},
			want: pluginArgs{filename: "/etc/ports.txt", key: "circuit-id"},
		},
		{
			name: "any order, with autorefresh",
			args: []string{"autorefresh", "key:remote-id", "file:ports.txt"},
			want: pluginArgs{filename: "ports.txt", key: "remote-id", refresh: true},
		},
		{
			name:    "unknown argument",
			args:    []string{"file:ports.txt", "key:remote-id", "refresh"},
			errText: "unexpected argument `refresh`",
		},
		{name: "no arguments", args: nil, wantErr: errNoFile},
		{name: "no file", args: []string{"key:circuit-id"}, wantErr: errNoFile},
		{name: "empty file", args: []string{"file:", "key:circuit-id"}, wantErr: errNoFile},
		{name: "no key", args: []string{"file:ports.txt"}, wantErr: errNoKey},
		{name: "empty key", args: []string{"file:ports.txt", "key:"}, wantErr: errNoKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgs(tc.args)
			switch {
			case tc.wantErr != nil:
				assert.ErrorIs(t, err, tc.wantErr)
			case tc.errText != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errText)
			default:
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// TestKeySource covers the per-family allow-lists, including remote-id being
// the one name both families accept.
func TestKeySource(t *testing.T) {
	t.Run("DHCPv4", func(t *testing.T) {
		for _, name := range []string{"circuit-id", "remote-id", "subscriber-id"} {
			fn, err := keySource("DHCPv4", name, keys4)
			require.NoError(t, err)
			assert.NotNil(t, fn)
		}
		_, err := keySource("DHCPv4", "interface-id", keys4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown DHCPv4 key `interface-id`")
		assert.Contains(t, err.Error(), "circuit-id, remote-id, subscriber-id")
	})

	t.Run("DHCPv6", func(t *testing.T) {
		for _, name := range []string{"interface-id", "remote-id"} {
			fn, err := keySource("DHCPv6", name, keys6)
			require.NoError(t, err)
			assert.NotNil(t, fn)
		}
		_, err := keySource("DHCPv6", "subscriber-id", keys6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown DHCPv6 key `subscriber-id`")
		assert.Contains(t, err.Error(), "interface-id, remote-id")
	})
}

func TestParseRecords(t *testing.T) {
	longKey := strings.Repeat("a", maxKeyLen)

	for _, tc := range []struct {
		name     string
		contents string
		v6       bool
		want     map[string]record
		errText  string
	}{
		{
			name:     "text key takes the default lease",
			contents: "rack4-sw1:eth3 192.0.2.31\n",
			want:     map[string]record{"rack4-sw1:eth3": {netip.MustParseAddr("192.0.2.31"), time.Hour}},
		},
		{
			name:     "hex key and per-line lease",
			contents: "0x0a0b0c 192.0.2.32 30m\n",
			want:     map[string]record{"\x0a\x0b\x0c": {netip.MustParseAddr("192.0.2.32"), 30 * time.Minute}},
		},
		{
			name:     "hex prefix and digits are case-insensitive",
			contents: "0XAaBb 192.0.2.33 90s\n",
			want:     map[string]record{"\xaa\xbb": {netip.MustParseAddr("192.0.2.33"), 90 * time.Second}},
		},
		{
			name:     "sub-second precision is rounded away",
			contents: "port-1 192.0.2.34 1500ms\n",
			want:     map[string]record{"port-1": {netip.MustParseAddr("192.0.2.34"), 2 * time.Second}},
		},
		{
			name: "comments and blank lines are ignored",
			contents: "# a full-line comment\n" +
				"\n" +
				"   \t \n" +
				"  port-1 192.0.2.35  # trailing comment\n" +
				"   # an indented comment\n",
			want: map[string]record{"port-1": {netip.MustParseAddr("192.0.2.35"), time.Hour}},
		},
		{
			name:     "a file of nothing but comments loads empty",
			contents: "# nothing here yet\n",
			want:     map[string]record{},
		},
		{
			name:     "duplicate key, last line wins",
			contents: "port-1 192.0.2.36\nport-1 192.0.2.37\n",
			want:     map[string]record{"port-1": {netip.MustParseAddr("192.0.2.37"), time.Hour}},
		},
		{
			name:     "duplicate address is kept",
			contents: "port-1 192.0.2.38\nport-2 192.0.2.38\n",
			want: map[string]record{
				"port-1": {netip.MustParseAddr("192.0.2.38"), time.Hour},
				"port-2": {netip.MustParseAddr("192.0.2.38"), time.Hour},
			},
		},
		{
			name:     "key at the length limit",
			contents: longKey + " 192.0.2.39\n",
			want:     map[string]record{longKey: {netip.MustParseAddr("192.0.2.39"), time.Hour}},
		},
		{
			name:     "IPv6 mapping",
			contents: "0x0004010203 2001:db8::31 12h\n",
			v6:       true,
			want:     map[string]record{"\x00\x04\x01\x02\x03": {netip.MustParseAddr("2001:db8::31"), 12 * time.Hour}},
		},
		{
			name:     "IPv4-mapped IPv6 address is an IPv6 address",
			contents: "port-1 ::ffff:192.0.2.40\n",
			v6:       true,
			want:     map[string]record{"port-1": {netip.MustParseAddr("::ffff:192.0.2.40"), time.Hour}},
		},

		{name: "only a key", contents: "port-1\n", errText: "line 1: malformed line, want `<key> <ip> [lease]`, got 1 fields"},
		{name: "one field too many", contents: "port-1 192.0.2.1 1h extra\n", errText: "line 1: malformed line"},
		{name: "odd number of hex digits", contents: "0xabc 192.0.2.1\n", errText: "malformed hex key 0xabc"},
		{name: "not a hex digit", contents: "0xzz 192.0.2.1\n", errText: "malformed hex key 0xzz"},
		{name: "empty hex key", contents: "0x 192.0.2.1\n", errText: "empty hex key: 0x"},
		{name: "unprintable byte in a text key", contents: "por\x01t 192.0.2.1\n", errText: "neither printable ASCII nor 0x-prefixed hex"},
		{
			name:     "key over the length limit",
			contents: longKey + "a 192.0.2.1\n",
			errText:  "key is 256 bytes, over the 255 byte limit",
		},
		{name: "not an address", contents: "port-1 no-such-address\n", errText: "expected an IPv4 address, got: no-such-address"},
		{name: "IPv6 address in a DHCPv4 file", contents: "port-1 2001:db8::1\n", errText: "expected an IPv4 address, got: 2001:db8::1"},
		{name: "IPv4 address in a DHCPv6 file", contents: "port-1 192.0.2.1\n", v6: true, errText: "expected an IPv6 address, got: 192.0.2.1"},
		{name: "not a duration", contents: "port-1 192.0.2.1 1year\n", errText: "malformed lease duration: 1year"},
		{name: "lease under a second", contents: "port-1 192.0.2.1 500ms\n", errText: "lease duration must be at least 1s, got: 500ms"},
		{name: "negative lease", contents: "port-1 192.0.2.1 -1h\n", errText: "lease duration must be at least 1s, got: -1h"},
		{
			name:     "the error names the offending line",
			contents: "port-1 192.0.2.1\n\n# comment\nport-2 not-an-address\n",
			errText:  "line 4: expected an IPv4 address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRecords(strings.NewReader(tc.contents), tc.v6)
			if tc.errText != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errText)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// errReader fails on the first read, which is how a mapping file on a failing
// disk reaches the scanner's error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }

func TestParseRecordsReadError(t *testing.T) {
	_, err := parseRecords(errReader{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated read failure")
}

func TestLoadRecordsMissingFile(t *testing.T) {
	_, err := loadRecords(filepath.Join(t.TempDir(), "absent.txt"), false)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestKeyText(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{name: "printable text is left alone", in: "rack4-sw1:eth3", want: "rack4-sw1:eth3"},
		{name: "binary becomes hex", in: "\x00\x04\x01", want: "0x000401"},
		{name: "a space is not printable here", in: "a b", want: "0x612062"},
		{name: "empty", in: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, keyText(tc.in))
		})
	}
}

// TestMatch covers the three ways a key fails to resolve, which the handlers
// share and which are otherwise only visible as a debug log line.
func TestMatch(t *testing.T) {
	s := &pluginState{
		keyName: "circuit-id",
		recs:    map[string]record{"port-1": {netip.MustParseAddr("192.0.2.1"), time.Hour}},
	}

	for _, tc := range []struct {
		name string
		key  []byte
		want bool
	}{
		{name: "no key in the request", key: nil},
		{name: "key over the wire limit", key: []byte(strings.Repeat("a", maxKeyLen+1))},
		{name: "key is not mapped", key: []byte("port-9")},
		{name: "key is mapped", key: []byte("port-1"), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := s.match(tc.key)
			assert.Equal(t, tc.want, ok)
			if tc.want {
				assert.Equal(t, netip.MustParseAddr("192.0.2.1"), rec.addr)
			}
		})
	}
}

// These two cases substitute the fsnotifyNewWatcher/watcherAdd seams to
// simulate autorefresh setup failures. Real filesystem operations cannot
// deterministically fail fsnotify.NewWatcher (an fd exhaustion condition) or
// Watcher.Add on a file that was just read successfully, so the production
// code exposes these as indirections purely for this test.

func TestSetupStateWatcherCreateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.txt")
	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\n"), 0o600))

	orig := fsnotifyNewWatcher
	t.Cleanup(func() { fsnotifyNewWatcher = orig })
	fsnotifyNewWatcher = func() (*fsnotify.Watcher, error) {
		return nil, errors.New("simulated watcher creation failure")
	}

	_, err := setupState(false, "file:"+path, "key:circuit-id", autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create watcher")
}

func TestSetupStateWatcherAddError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.txt")
	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\n"), 0o600))

	orig := watcherAdd
	t.Cleanup(func() { watcherAdd = orig })
	watcherAdd = func(*fsnotify.Watcher, string) error {
		return errors.New("simulated watch failure")
	}

	_, err := setupState(false, "file:"+path, "key:circuit-id", autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to watch")
}
