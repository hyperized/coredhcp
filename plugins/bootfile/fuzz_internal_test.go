// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bootfile

import (
	"maps"
	"slices"
	"testing"
)

// FuzzParseArgs feeds arbitrary argument pairs to parseArgs and to the two
// encoders that consume its result. The invariants: never panic, and on
// success every argument produced exactly one entry whose URL uses one of the
// allowed schemes, since that is what the handlers rely on when they decide
// whether to split a URL across DHCPv4 options 66 and 67.
func FuzzParseArgs(f *testing.F) {
	for _, seed := range [][2]string{
		{"x86-bios=tftp://10.0.0.5/undionly.kpxe", "default=http://boot.example/ipxe.efi"},
		{"arch:7=tftp://10.0.0.5/ipxe.efi", "arch:07=tftp://10.0.0.5/ipxe.efi"},
		{"ipxe=https://boot.example/boot.ipxe?params=a=b", "arm64-uefi=ftp://10.0.0.5/f"},
		{"x86-bios=tftp://[2001:db8::5]/f", "x86-uefi=tftp://[::1%25eth0]/f"},
		{"", "="},
		{"=tftp://a/b", "x86-bios=nfs://a/b"},
		{"arch:65536=tftp://a/b", "arch:-0=tftp://a/b"},
		{"x86-bios=tftp://[::1", "\x00=\x00"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, first, second string) {
		b, err := parseArgs(first, second)
		if err != nil {
			return
		}
		if b.count() != 2 {
			t.Fatalf("parseArgs(%q, %q) accepted two arguments but produced %d entries", first, second, b.count())
		}
		for _, u := range append(slices.Collect(maps.Values(b.byArch)), b.ipxe, b.def) {
			if u == nil {
				continue
			}
			if !slices.Contains(bootSchemes, u.Scheme) {
				t.Fatalf("parseArgs(%q, %q) accepted scheme %q", first, second, u.Scheme)
			}
			newEntry4(u)
			newEntry6(u)
		}
	})
}
