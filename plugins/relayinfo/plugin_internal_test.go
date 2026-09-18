// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package relayinfo

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
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
			args: []string{"file:/etc/ports.txt", "key:circuit-id", "allow", "10.0.1.1"},
			want: pluginArgs{
				filename: "/etc/ports.txt",
				key:      "circuit-id",
				allow4:   []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
				sawAllow: true,
			},
		},
		{
			name: "any order, with autorefresh",
			args: []string{"autorefresh", "key:remote-id", "allow", "10.0.1.1", "file:ports.txt"},
			want: pluginArgs{
				filename: "ports.txt",
				key:      "remote-id",
				refresh:  true,
				allow4:   []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
				sawAllow: true,
			},
		},
		{
			name: "allow with a single address",
			args: []string{"file:ports.txt", "key:circuit-id", "allow", "10.0.2.2"},
			want: pluginArgs{
				filename: "ports.txt",
				key:      "circuit-id",
				allow4:   []netip.Prefix{netip.MustParsePrefix("10.0.2.2/32")},
				sawAllow: true,
			},
		},
		{
			name: "allow with a mix of families and a CIDR",
			args: []string{"file:ports.txt", "key:circuit-id", "allow", "10.0.1.1", "2001:db8::1", "10.0.2.0/24"},
			want: pluginArgs{
				filename: "ports.txt",
				key:      "circuit-id",
				allow4:   []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32"), netip.MustParsePrefix("10.0.2.0/24")},
				allow6:   []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
				sawAllow: true,
			},
		},
		{
			name: "a named argument after allow is still named, not an address",
			args: []string{"file:ports.txt", "key:circuit-id", "allow", "10.0.1.1", "autorefresh"},
			want: pluginArgs{
				filename: "ports.txt",
				key:      "circuit-id",
				refresh:  true,
				allow4:   []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
				sawAllow: true,
			},
		},
		{
			name:    "unknown argument",
			args:    []string{"file:ports.txt", "key:remote-id", "refresh"},
			errText: `argument "refresh" is not recognised`,
		},
		{
			name:    "bare argument before allow is still unexpected",
			args:    []string{"file:ports.txt", "key:circuit-id", "typo", "allow", "10.0.1.1"},
			errText: `argument "typo" is not recognised`,
		},
		{name: "no arguments", args: nil, wantErr: errNoFile},
		{name: "no file", args: []string{"key:circuit-id"}, wantErr: errNoFile},
		{name: "empty file", args: []string{"file:", "key:circuit-id"}, wantErr: errNoFile},
		{name: "no key", args: []string{"file:ports.txt"}, wantErr: errNoKey},
		{name: "empty key", args: []string{"file:ports.txt", "key:"}, wantErr: errNoKey},
		{name: "no allow", args: []string{"file:ports.txt", "key:circuit-id"}, wantErr: errNoAllow},
		{
			name:    "malformed address after allow",
			args:    []string{"file:ports.txt", "key:circuit-id", "allow", "not-an-address"},
			errText: `allow list entry "not-an-address" does not parse`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgs(tc.args)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
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
		assert.Contains(t, err.Error(), `DHCPv4 key "interface-id" is not recognised`)
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
		assert.Contains(t, err.Error(), `DHCPv6 key "subscriber-id" is not recognised`)
		assert.Contains(t, err.Error(), "interface-id, remote-id")
	})
}

// TestParseAllowEntry also covers two syntactically valid spellings that are
// refused because they would never match a real peer address.
func TestParseAllowEntry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arg     string
		want    string
		wantErr error
		errText string
	}{
		{name: "a bare IPv4 address becomes a /32", arg: "10.0.1.1", want: "10.0.1.1/32"},
		{name: "a bare IPv6 address becomes a /128", arg: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "a CIDR is masked down to its network", arg: "10.0.2.5/24", want: "10.0.2.0/24"},
		{name: "malformed prefix", arg: "10.0.0.0/99", errText: `allow list prefix "10.0.0.0/99" does not parse`},
		{name: "malformed address", arg: "not-an-address", errText: `allow list entry "not-an-address" does not parse`},
		{
			name:    "an IPv4-mapped IPv6 address",
			arg:     "::ffff:10.0.0.1",
			wantErr: errMappedEntry,
			errText: `address "::ffff:10.0.0.1"`,
		},
		{
			name:    "an IPv4-mapped IPv6 prefix",
			arg:     "::ffff:10.0.0.0/104",
			wantErr: errMappedEntry,
			errText: `prefix "::ffff:10.0.0.0/104"`,
		},
		{
			name:    "a zoned address",
			arg:     "fe80::1%eth0",
			wantErr: errZonedEntry,
			errText: `address "fe80::1%eth0"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAllowEntry(tc.arg)
			if tc.wantErr != nil || tc.errText != "" {
				require.Error(t, err)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
				}
				if tc.errText != "" {
					assert.Contains(t, err.Error(), tc.errText)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestAllowFor(t *testing.T) {
	a := pluginArgs{
		allow4: []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
		allow6: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
	}
	assert.Equal(t, a.allow4, a.allowFor(false))
	assert.Equal(t, a.allow6, a.allowFor(true))
}

func TestFamilyName(t *testing.T) {
	assert.Equal(t, "DHCPv4", familyName(false))
	assert.Equal(t, "DHCPv6", familyName(true))
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

		{name: "only a key", contents: "port-1\n", errText: `line 1: "port-1" has 1 fields`},
		{name: "one field too many", contents: "port-1 192.0.2.1 1h extra\n", errText: `line 1: "port-1 192.0.2.1 1h extra" has 4 fields`},
		{name: "odd number of hex digits", contents: "0xabc 192.0.2.1\n", errText: `hex key "0xabc" is not hexadecimal`},
		{name: "not a hex digit", contents: "0xzz 192.0.2.1\n", errText: `hex key "0xzz" is not hexadecimal`},
		{name: "empty hex key", contents: "0x 192.0.2.1\n", errText: `hex key "0x" has no digits`},
		{name: "unprintable byte in a text key", contents: "por\x01t 192.0.2.1\n", errText: "neither printable ASCII nor 0x-prefixed hex"},
		{
			name:     "key over the length limit",
			contents: longKey + "a 192.0.2.1\n",
			errText:  "is 256 bytes, over the 255 byte limit",
		},
		{name: "not an address", contents: "port-1 no-such-address\n", errText: `"no-such-address" is not an IP address`},
		{name: "IPv6 address in a DHCPv4 file", contents: "port-1 2001:db8::1\n", errText: "2001:db8::1 is not an IPv4 address"},
		{name: "IPv4 address in a DHCPv6 file", contents: "port-1 192.0.2.1\n", v6: true, errText: "192.0.2.1 is not an IPv6 address"},
		{name: "not a duration", contents: "port-1 192.0.2.1 1year\n", errText: `lease "1year" is not a duration`},
		{name: "lease under a second", contents: "port-1 192.0.2.1 500ms\n", errText: `lease "500ms" is under the one second resolution`},
		{name: "negative lease", contents: "port-1 192.0.2.1 -1h\n", errText: `lease "-1h" is under the one second resolution`},
		{
			name:     "the error names the offending line",
			contents: "port-1 192.0.2.1\n\n# comment\nport-2 not-an-address\n",
			errText:  `line 4: "not-an-address" is not an IP address`,
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

func TestDropLimiter(t *testing.T) {
	var now time.Time
	clock := func() time.Time { return now }
	now = time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	limiter := newDropLimiter(clock)

	assert.True(t, limiter.allow(reasonNoRequestInfo), "a reason not seen before is always allowed")
	assert.False(t, limiter.allow(reasonNoRequestInfo), "the same reason inside the interval is refused")
	assert.True(t, limiter.allow(reasonPeerNotAllowed), "a different reason has its own budget")

	now = now.Add(logInterval - time.Nanosecond)
	assert.False(t, limiter.allow(reasonNoRequestInfo), "still inside the interval")

	now = now.Add(time.Nanosecond)
	assert.True(t, limiter.allow(reasonNoRequestInfo), "the interval has passed")
}

func ctxFromPeer(t *testing.T, peer string) context.Context {
	t.Helper()
	return handler.WithRequestInfo(t.Context(), handler.RequestInfo{Peer: netip.MustParseAddrPort(peer)})
}

func TestFromAllowedRelay(t *testing.T) {
	s := &pluginState{
		allow:   []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")},
		limiter: newDropLimiter(time.Now),
	}

	t.Run("allowed peer", func(t *testing.T) {
		assert.True(t, s.fromAllowedRelay(ctxFromPeer(t, "10.0.1.1:67")))
	})

	t.Run("disallowed peer", func(t *testing.T) {
		assert.False(t, s.fromAllowedRelay(ctxFromPeer(t, "10.0.9.9:67")))
	})

	t.Run("no request information at all", func(t *testing.T) {
		assert.False(t, s.fromAllowedRelay(t.Context()))
	})

	// The socket can hand back an IPv4 peer written in IPv4-mapped IPv6 form.
	// Unmap() in fromAllowedRelay is what still matches it against a plain
	// IPv4 entry.
	t.Run("an IPv4-mapped peer matches a plain IPv4 entry", func(t *testing.T) {
		assert.True(t, s.fromAllowedRelay(ctxFromPeer(t, "[::ffff:10.0.1.1]:67")))
	})
}

// TestSetupStateNoAllowEntriesForFamily pins that the check runs before the
// mapping file is ever opened.
func TestSetupStateNoAllowEntriesForFamily(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.txt")

	_, err := setupState(true, "file:"+path, "key:interface-id", "allow", "10.0.1.1")
	require.Error(t, err)
	require.ErrorIs(t, err, errNoAllowEntries)
	assert.Contains(t, err.Error(), "DHCPv6")
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

	_, err := setupState(false, "file:"+path, "key:circuit-id", "allow", "10.0.1.1", autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create a file watcher for autorefresh")
}

func TestSetupStateWatcherAddError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.txt")
	require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\n"), 0o600))

	orig := watcherAdd
	t.Cleanup(func() { watcherAdd = orig })
	watcherAdd = func(*fsnotify.Watcher, string) error {
		return errors.New("simulated watch failure")
	}

	_, err := setupState(false, "file:"+path, "key:circuit-id", "allow", "10.0.1.1", autoRefreshArg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "for changes: simulated watch failure")
}

// TestWatchLoop uses a bare *fsnotify.Watcher rather than one from
// fsnotify.NewWatcher: the real one starts a platform goroutine that also
// writes into Events and Errors, racing with the test's own sends. watchLoop
// only ever reads those two fields, so it cannot tell the difference.
func TestWatchLoop(t *testing.T) {
	newState := func(t *testing.T, dir string) (*pluginState, string) {
		t.Helper()
		path := filepath.Join(dir, "ports.txt")
		require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\n"), 0o600))
		s := &pluginState{keyName: "circuit-id"}
		require.NoError(t, s.loadFromFile(false, path))
		return s, path
	}

	newWatcher := func() *fsnotify.Watcher {
		return &fsnotify.Watcher{Events: make(chan fsnotify.Event), Errors: make(chan error)}
	}

	// Each returned closer closes its channel exactly once, so a subtest can
	// close one early without a double-close panic from the cleanup. The wait
	// is registered before the close, since t.Cleanup runs LIFO: a loop that
	// never exits then fails the test instead of leaking silently.
	startLoop := func(t *testing.T, s *pluginState, path string, watcher *fsnotify.Watcher) (done chan struct{}, closeEvents, closeErrors func()) {
		t.Helper()
		done = make(chan struct{})
		go func() {
			defer close(done)
			s.watchLoop(false, path, watcher)
		}()

		var onceEvents, onceErrors sync.Once
		closeEvents = func() { onceEvents.Do(func() { close(watcher.Events) }) }
		closeErrors = func() { onceErrors.Do(func() { close(watcher.Errors) }) }
		t.Cleanup(func() {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("watchLoop did not return after the channels were closed")
			}
		})
		t.Cleanup(func() {
			closeEvents()
			closeErrors()
		})
		return done, closeEvents, closeErrors
	}

	t.Run("an error is logged and the loop keeps reading afterward", func(t *testing.T) {
		dir := t.TempDir()
		s, path := newState(t, dir)

		logPath := filepath.Join(dir, "plugin.log")
		require.NoError(t, logger.WithFile(logPath))
		t.Cleanup(func() { _ = logger.WithFile(os.DevNull) })

		watcher := newWatcher()
		startLoop(t, s, path, watcher)

		watcher.Errors <- errors.New("simulated queue overflow")
		require.Eventually(t, func() bool {
			data, err := os.ReadFile(logPath)
			return err == nil && strings.Contains(string(data), "reported an error")
		}, 5*time.Second, 20*time.Millisecond, "the error was not logged")

		// Before the fix, watchLoop never read Errors, so fsnotify's dispatch
		// goroutine parked on that unbuffered send and no later event was
		// ever delivered either.
		require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\nport-2 192.0.2.2\n"), 0o600))
		watcher.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 2 }, 5*time.Second, 20*time.Millisecond,
			"the loop did not reload after the error")
	})

	t.Run("an event for another file in the same directory triggers no reload", func(t *testing.T) {
		dir := t.TempDir()
		s, path := newState(t, dir)

		watcher := newWatcher()
		startLoop(t, s, path, watcher)

		watcher.Events <- fsnotify.Event{Name: filepath.Join(dir, "other.txt"), Op: fsnotify.Write}

		// There is no positive signal to wait for, so give a wrongly-triggered
		// reload a moment to happen before proving the loop still reads.
		time.Sleep(20 * time.Millisecond)
		assert.Equal(t, 1, s.numRecords())

		require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\nport-2 192.0.2.2\n"), 0o600))
		watcher.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 2 }, 5*time.Second, 20*time.Millisecond,
			"the loop stopped reading events")
	})

	t.Run("an event for the watched file triggers a reload", func(t *testing.T) {
		dir := t.TempDir()
		s, path := newState(t, dir)

		watcher := newWatcher()
		startLoop(t, s, path, watcher)

		require.NoError(t, os.WriteFile(path, []byte("port-1 192.0.2.1\nport-2 192.0.2.2\n"), 0o600))
		watcher.Events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		require.Eventually(t, func() bool { return s.numRecords() == 2 }, 5*time.Second, 20*time.Millisecond,
			"the event did not trigger a reload")
	})

	t.Run("closing the events channel makes the loop return", func(t *testing.T) {
		dir := t.TempDir()
		s, path := newState(t, dir)

		watcher := newWatcher()
		done, closeEvents, _ := startLoop(t, s, path, watcher)

		closeEvents()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("watchLoop did not return after Events was closed")
		}
	})

	t.Run("closing the errors channel makes the loop return", func(t *testing.T) {
		dir := t.TempDir()
		s, path := newState(t, dir)

		watcher := newWatcher()
		done, _, closeErrors := startLoop(t, s, path, watcher)

		closeErrors()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("watchLoop did not return after Errors was closed")
		}
	})
}

// TestGiaddrSet pins the three spellings an unset giaddr arrives in:
// net.IP.IsUnspecified answers false for the nil one, so reading the field
// directly would have marked an on-link request relayed.
func TestGiaddrSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
		want bool
	}{
		{name: "nil", ip: nil},
		{name: "four zero bytes", ip: net.IPv4zero.To4()},
		{name: "sixteen zero bytes", ip: net.IPv6unspecified},
		{name: "a wrong-length slice", ip: net.IP{1, 2, 3}},
		{name: "an IPv4 relay", ip: net.ParseIP("10.0.1.1"), want: true},
		{name: "an IPv4 relay in four-byte form", ip: net.ParseIP("10.0.1.1").To4(), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, giaddrSet(tc.ip))
		})
	}
}

func TestRelayed4(t *testing.T) {
	newReq := func(t *testing.T) *dhcpv4.DHCPv4 {
		t.Helper()
		req, err := dhcpv4.New()
		require.NoError(t, err)
		return req
	}

	for _, tc := range []struct {
		name string
		mark func(*dhcpv4.DHCPv4)
		want bool
	}{
		{name: "neither option 82 nor giaddr", mark: func(*dhcpv4.DHCPv4) {}},
		{
			name: "option 82 alone",
			mark: func(req *dhcpv4.DHCPv4) {
				req.UpdateOption(dhcpv4.OptRelayAgentInfo(
					dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("rack4-sw1:eth3"))))
			},
			want: true,
		},
		{
			name: "giaddr alone",
			mark: func(req *dhcpv4.DHCPv4) { req.GatewayIPAddr = net.ParseIP("10.0.1.1") },
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq(t)
			tc.mark(req)
			assert.Equal(t, tc.want, relayed4(req))
		})
	}
}
