// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverconf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/test/all/internal/serverconf"
)

// fixture is a trimmed copy of the test stack's own rendered configuration:
// two plugins carrying scalar and list-like arguments, one repeated plugin
// name, and one integer value where the server sees every other value as a
// string.
const fixture = `
server4:
    listen:
        - "%eth0"
    plugins:
        - metrics: unix:/run/coredhcp/metrics.sock mode:0666
        - ratelimit: 100/s burst:200 per:mac global:100/s
        - mtu: 1400
        - server_id: 172.31.246.2
        - dns: 172.31.246.1 9.9.9.9
        - leasehook: url:http://helper:8080/hook secret:env:HOOK timeout:2s
        - leasehook: exec:/opt/hooks/lease-exec timeout:5s
        - range: /var/lib/coredhcp/leases4.sqlite3 172.31.246.100 172.31.246.140 5m
server6:
    plugins:
        - range6: /var/lib/coredhcp/leases6.sqlite3 fd00:c0de:246::1000 fd00:c0de:246::1040 5m
`

func TestParse(t *testing.T) {
	t.Run("a realistic configuration", func(t *testing.T) {
		cfg, err := serverconf.Parse([]byte(fixture))
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, []string{
			"metrics", "ratelimit", "mtu", "server_id", "dns", "leasehook", "leasehook", "range",
		}, cfg.Server4.Names())
		assert.Equal(t, []string{"range6"}, cfg.Server6.Names())
	})

	t.Run("yaml that does not parse", func(t *testing.T) {
		// A tab in the indentation is invalid YAML block syntax, unlike
		// almost any other malformed input, so this failure is reliable.
		_, err := serverconf.Parse([]byte("server4:\n\tplugins: []\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing the server configuration")
	})

	t.Run("only server4 is present", func(t *testing.T) {
		cfg, err := serverconf.Parse([]byte("server4:\n    plugins:\n        - mtu: 1400\n"))
		require.NoError(t, err)
		assert.Nil(t, cfg.Server6)
	})

	t.Run("a section with no plugins key", func(t *testing.T) {
		cfg, err := serverconf.Parse([]byte("server4: {}\n"))
		require.NoError(t, err)
		assert.Empty(t, cfg.Server4)
	})

	t.Run("a server4 plugin item with two names", func(t *testing.T) {
		_, err := serverconf.Parse([]byte("server4:\n    plugins:\n        - a: 1\n          b: 2\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server4 plugin #1 holds 2 names")
	})

	t.Run("a server6 plugin item with two names", func(t *testing.T) {
		_, err := serverconf.Parse([]byte("server6:\n    plugins:\n        - a: 1\n          b: 2\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server6 plugin #1 holds 2 names")
	})
}

func TestLoad(t *testing.T) {
	t.Run("reads and parses a rendered config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(fixture), 0o600))

		cfg, err := serverconf.Load(path)
		require.NoError(t, err)
		assert.True(t, cfg.Server4.Has("mtu"))
	})

	t.Run("a path that does not exist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.yaml")

		_, err := serverconf.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), path)
	})

	t.Run("a file that does not parse", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte("server4:\n\tplugins: []\n"), 0o600))

		_, err := serverconf.Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), path)
	})
}

func TestChain(t *testing.T) {
	cfg, err := serverconf.Parse([]byte(fixture))
	require.NoError(t, err)
	chain := cfg.Server4

	t.Run("Has", func(t *testing.T) {
		assert.True(t, chain.Has("mtu"))
		assert.False(t, chain.Has("nbp"))
	})

	t.Run("First", func(t *testing.T) {
		args, ok := chain.First("leasehook")
		require.True(t, ok)
		assert.Equal(t, []string{"url:http://helper:8080/hook", "secret:env:HOOK", "timeout:2s"}, args)

		_, ok = chain.First("nbp")
		assert.False(t, ok)
	})

	t.Run("All", func(t *testing.T) {
		all := chain.All("leasehook")
		require.Len(t, all, 2)
		assert.Equal(t, []string{"url:http://helper:8080/hook", "secret:env:HOOK", "timeout:2s"}, all[0])
		assert.Equal(t, []string{"exec:/opt/hooks/lease-exec", "timeout:5s"}, all[1])

		assert.Nil(t, chain.All("nbp"))
	})

	t.Run("Arg", func(t *testing.T) {
		v, ok := chain.Arg("range", 2)
		require.True(t, ok)
		assert.Equal(t, "172.31.246.140", v)

		_, ok = chain.Arg("range", 99)
		assert.False(t, ok, "an out-of-range index is a miss, not a panic")

		_, ok = chain.Arg("nbp", 0)
		assert.False(t, ok)
	})

	t.Run("MustArg", func(t *testing.T) {
		v, err := chain.MustArg("mtu", 0)
		require.NoError(t, err)
		assert.Equal(t, "1400", v)

		_, err = chain.MustArg("nbp", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"nbp"`)
	})

	t.Run("Named", func(t *testing.T) {
		v, ok := chain.Named("ratelimit", "burst")
		require.True(t, ok)
		assert.Equal(t, "200", v)

		v, ok = chain.Named("leasehook", "url")
		require.True(t, ok)
		assert.Equal(t, "http://helper:8080/hook", v, "Named looks at the first leasehook only")

		_, ok = chain.Named("mtu", "nonexistent")
		assert.False(t, ok)

		_, ok = chain.Named("nbp", "burst")
		assert.False(t, ok)
	})

	t.Run("Index", func(t *testing.T) {
		assert.Equal(t, 0, chain.Index("metrics"))
		assert.Equal(t, -1, chain.Index("nbp"))
	})

	t.Run("Names", func(t *testing.T) {
		assert.Equal(t, []string{
			"metrics", "ratelimit", "mtu", "server_id", "dns", "leasehook", "leasehook", "range",
		}, chain.Names())
	})
}
