// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bootfile

import (
	"net"
	"net/url"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestParseArgsErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want error
	}{
		{"no arguments", nil, errNoEntries},
		{"missing equals sign", []string{"x86-bios"}, errMalformedEntry},
		{"unknown key", []string{"sparc=tftp://10.0.0.5/f"}, errUnknownKey},
		{"architecture code is not a number", []string{"arch:x86=tftp://10.0.0.5/f"}, errBadArchCode},
		{"architecture code out of range", []string{"arch:70000=tftp://10.0.0.5/f"}, errBadArchCode},
		{"architecture code is negative", []string{"arch:-1=tftp://10.0.0.5/f"}, errBadArchCode},
		{"malformed URL", []string{"x86-bios=tftp://[::1"}, errBadURL},
		{"unsupported scheme", []string{"x86-bios=nfs://10.0.0.5/f"}, errBadScheme},
		{"empty URL", []string{"x86-bios="}, errBadScheme},
		{"duplicate architecture name", []string{"x86-bios=tftp://a/f", "x86-bios=tftp://b/f"}, errDuplicateKey},
		{"duplicate architecture by code", []string{"x86-64-uefi=tftp://a/f", "arch:7=tftp://b/f"}, errDuplicateKey},
		{"duplicate ipxe", []string{"ipxe=http://a/s", "ipxe=http://b/s"}, errDuplicateKey},
		{"duplicate default", []string{"default=tftp://a/f", "default=tftp://b/f"}, errDuplicateKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := parseArgs(tc.args...)
			assert.Nil(t, b)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestParseArgsErrorNamesTheOffendingInput(t *testing.T) {
	_, err := parseArgs("sparc=tftp://10.0.0.5/f")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"sparc"`)
	assert.Contains(t, err.Error(), "arch:<n>")
}

func TestParseArgs(t *testing.T) {
	b, err := parseArgs(
		"default=tftp://10.0.0.5/undionly.kpxe",
		"x86-64-uefi=tftp://10.0.0.5/ipxe.efi",
		"arch:27=tftp://10.0.0.5/ipxe-riscv.efi",
		"ipxe=http://boot.example/boot.ipxe",
	)
	require.NoError(t, err)
	require.NotNil(t, b)

	require.Len(t, b.byArch, 2)
	assert.Equal(t, "tftp://10.0.0.5/ipxe.efi", b.byArch[iana.EFI_X86_64].String())
	assert.Equal(t, "tftp://10.0.0.5/ipxe-riscv.efi", b.byArch[iana.EFI_RISCV64].String())
	require.NotNil(t, b.ipxe)
	assert.Equal(t, "http://boot.example/boot.ipxe", b.ipxe.String())
	require.NotNil(t, b.def)
	assert.Equal(t, "tftp://10.0.0.5/undionly.kpxe", b.def.String())
	assert.Equal(t, 4, b.count())
}

func TestBootFilesCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"architectures only", []string{"x86-bios=tftp://a/f", "arm64-uefi=tftp://a/g"}, 2},
		{"ipxe only", []string{"ipxe=http://a/s"}, 1},
		{"default only", []string{"default=tftp://a/f"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := parseArgs(tc.args...)
			require.NoError(t, err)
			assert.Equal(t, tc.want, b.count())
		})
	}
}

func TestParseArch(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		want iana.Arch
	}{
		{"x86-bios", "x86-bios", iana.INTEL_X86PC},
		{"x86-uefi", "x86-uefi", iana.EFI_IA32},
		{"x86-64-uefi", "x86-64-uefi", iana.EFI_X86_64},
		{"arm32-uefi", "arm32-uefi", iana.EFI_ARM32},
		{"arm64-uefi", "arm64-uefi", iana.EFI_ARM64},
		{"x86-http", "x86-http", iana.EFI_X86_HTTP},
		{"x86-64-http", "x86-64-http", iana.EFI_X86_64_HTTP},
		{"arm32-http", "arm32-http", iana.EFI_ARM32_HTTP},
		{"arm64-http", "arm64-http", iana.EFI_ARM64_HTTP},
		{"riscv64-uefi", "riscv64-uefi", iana.EFI_RISCV64},
		{"riscv64-http", "riscv64-http", iana.EFI_RISCV64_HTTP},
		{"lowest numeric code", "arch:0", iana.INTEL_X86PC},
		{"highest numeric code", "arch:65535", iana.Arch(65535)},
		{"numeric code for a named architecture", "arch:11", iana.EFI_ARM64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch, err := parseArch(tc.key)
			require.NoError(t, err)
			assert.Equal(t, tc.want, arch)
		})
	}
}

func TestKnownKeys(t *testing.T) {
	keys := knownKeys()
	assert.Equal(t, keys, knownKeys(), "must not depend on map iteration order")
	assert.Contains(t, keys, "arm64-uefi")
	assert.Contains(t, keys, "ipxe")
	assert.Contains(t, keys, "default")
	assert.Contains(t, keys, "arch:<n>")
}

func TestParseURL(t *testing.T) {
	for _, scheme := range bootSchemes {
		t.Run(scheme, func(t *testing.T) {
			u, err := parseURL(scheme + "://10.0.0.5/boot")
			require.NoError(t, err)
			assert.Equal(t, scheme, u.Scheme)
		})
	}
}

func TestSelectorPick(t *testing.T) {
	full := selector[string]{
		byArch: map[iana.Arch]string{
			iana.INTEL_X86PC: "bios",
			iana.EFI_X86_64:  "uefi",
		},
		ipxe:       "script",
		hasIPXE:    true,
		fallback:   "fallback",
		hasDefault: true,
	}
	noIPXE := full
	noIPXE.ipxe, noIPXE.hasIPXE = "", false
	bare := selector[string]{byArch: map[iana.Arch]string{iana.EFI_X86_64: "uefi"}}

	for _, tc := range []struct {
		name   string
		sel    selector[string]
		isIPXE bool
		archs  []iana.Arch
		want   string
		wantOK bool
	}{
		{"ipxe beats the architecture", full, true, []iana.Arch{iana.EFI_X86_64}, "script", true},
		{"ipxe client without an ipxe entry falls back to the architecture", noIPXE, true,
			[]iana.Arch{iana.EFI_X86_64}, "uefi", true},
		{"first configured architecture wins", full, false,
			[]iana.Arch{iana.EFI_ARM64, iana.INTEL_X86PC, iana.EFI_X86_64}, "bios", true},
		{"unmatched architecture falls back to default", full, false,
			[]iana.Arch{iana.EFI_ARM64}, "fallback", true},
		{"no architecture at all falls back to default", full, false, nil, "fallback", true},
		{"no match and no default selects nothing", bare, true, []iana.Arch{iana.EFI_ARM64}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.sel.pick(tc.isIPXE, tc.archs)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompile(t *testing.T) {
	t.Run("every entry configured", func(t *testing.T) {
		b, err := parseArgs("x86-bios=tftp://a/f", "ipxe=http://a/s", "default=tftp://a/d")
		require.NoError(t, err)
		s := compile(b, func(u *url.URL) string { return u.String() })
		assert.Equal(t, map[iana.Arch]string{iana.INTEL_X86PC: "tftp://a/f"}, s.byArch)
		assert.True(t, s.hasIPXE)
		assert.Equal(t, "http://a/s", s.ipxe)
		assert.True(t, s.hasDefault)
		assert.Equal(t, "tftp://a/d", s.fallback)
	})

	t.Run("architectures only", func(t *testing.T) {
		b, err := parseArgs("x86-bios=tftp://a/f")
		require.NoError(t, err)
		s := compile(b, func(u *url.URL) string { return u.String() })
		assert.False(t, s.hasIPXE)
		assert.False(t, s.hasDefault)
	})
}

func TestIsHTTPBoot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		archs []iana.Arch
		want  bool
	}{
		{"no architecture", nil, false},
		{"bios", []iana.Arch{iana.INTEL_X86PC}, false},
		{"uefi over tftp", []iana.Arch{iana.EFI_X86_64}, false},
		{"uefi over http", []iana.Arch{iana.EFI_X86_64_HTTP}, true},
		{"riscv over http", []iana.Arch{iana.EFI_RISCV64_HTTP}, true},
		{"http listed after a tftp architecture", []iana.Arch{iana.EFI_X86_64, iana.EFI_X86_64_HTTP}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isHTTPBoot(tc.archs))
		})
	}
}

func TestNewEntry4(t *testing.T) {
	t.Run("tftp is split over two options", func(t *testing.T) {
		e := newEntry4(mustParseURL(t, "tftp://10.0.0.5/pxe/undionly.kpxe"))
		require.NotNil(t, e.tftpServer)
		assert.Equal(t, "10.0.0.5", string(e.tftpServer.Value.ToBytes()))
		assert.Equal(t, "/pxe/undionly.kpxe", string(e.bootFile.Value.ToBytes()))
	})

	t.Run("http travels whole", func(t *testing.T) {
		e := newEntry4(mustParseURL(t, "http://boot.example/ipxe.efi"))
		assert.Nil(t, e.tftpServer)
		assert.Equal(t, "http://boot.example/ipxe.efi", string(e.bootFile.Value.ToBytes()))
	})
}

func TestNewEntry6(t *testing.T) {
	t.Run("without params", func(t *testing.T) {
		e := newEntry6(mustParseURL(t, "tftp://[2001:db8::1]/ipxe.efi"))
		assert.Equal(t, "tftp://[2001:db8::1]/ipxe.efi", string(e.bootFileURL.ToBytes()))
		assert.Nil(t, e.param)
	})

	t.Run("with params", func(t *testing.T) {
		e := newEntry6(mustParseURL(t, "tftp://[2001:db8::1]/ipxe.efi?params=console=ttyS0"))
		require.NotNil(t, e.param)
		assert.Equal(t, "console=ttyS0", string(e.param.ToBytes()))
	})
}

func TestIsIPXE4(t *testing.T) {
	for _, tc := range []struct {
		name      string
		userClass string
		classID   string
		want      bool
	}{
		{"plain pxe client", "", "PXEClient:Arch:00007:UNDI:003000", false},
		{"user class", "iPXE", "", true},
		{"decorated user class", "iPXE-chained", "", true},
		{"vendor class prefix", "", "iPXE", true},
		{"vendor class naming ipxe later does not count", "", "PXEClient:iPXE", false},
		{"nothing at all", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
			require.NoError(t, err)
			if tc.userClass != "" {
				req.UpdateOption(dhcpv4.OptUserClass(tc.userClass))
			}
			if tc.classID != "" {
				req.UpdateOption(dhcpv4.OptClassIdentifier(tc.classID))
			}
			assert.Equal(t, tc.want, isIPXE4(req))
		})
	}
}

func TestIsIPXE6(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []dhcpv6.Option
		want    bool
	}{
		{"no class options", nil, false},
		{"user class", []dhcpv6.Option{
			&dhcpv6.OptUserClass{UserClasses: [][]byte{[]byte("iPXE")}},
		}, true},
		{"other user class", []dhcpv6.Option{
			&dhcpv6.OptUserClass{UserClasses: [][]byte{[]byte("gPXE")}},
		}, false},
		{"vendor class", []dhcpv6.Option{
			&dhcpv6.OptVendorClass{EnterpriseNumber: 343, Data: [][]byte{[]byte("iPXE")}},
		}, true},
		{"other vendor class", []dhcpv6.Option{
			&dhcpv6.OptVendorClass{EnterpriseNumber: 343, Data: [][]byte{[]byte("HTTPClient")}},
		}, false},
		{"ipxe in the second vendor class value", []dhcpv6.Option{
			&dhcpv6.OptVendorClass{EnterpriseNumber: 343, Data: [][]byte{[]byte("PXEClient"), []byte("iPXE")}},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := dhcpv6.NewMessage()
			require.NoError(t, err)
			for _, opt := range tc.options {
				msg.AddOption(opt)
			}
			assert.Equal(t, tc.want, isIPXE6(msg))
		})
	}
}
