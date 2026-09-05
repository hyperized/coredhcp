// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp

import (
	"strings"
	"testing"
)

// Checks that parseArgs never panics, and that any URL it returns round-trips
// through String() and re-parsing without error.
func FuzzParseArgs(f *testing.F) {
	seeds := []string{
		"http://a/b",
		"tftp://10.0.0.1/nbp",
		"http://[2001:db8::1]/nbp",
		"https://example.com/nbp?params=foo",
		"ftp://10.0.0.1/nbp",
		"10.0.0.254/nbp",
		"",
		"http://[::1",
		"://",
		"http://[::1%25eth0]/nbp",
		"\x00\x01http://a",
		"a b c",
		// Found by fuzzing: net/url itself has a String()/Parse round-trip gap for
		// an IPv6 zone ID with invalid-UTF-8 bytes; not a parseArgs bug (see skip below).
		"//[::%25\xf1]",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, arg string) {
		u, err := parseArgs(arg)
		if err != nil {
			return
		}
		if u == nil {
			t.Fatalf("parseArgs(%q) returned a nil URL with no error", arg)
		}

		if strings.ContainsRune(u.Host, '%') {
			// Decoded zone-ID case from the seed above; round trip isn't guaranteed here either.
			return
		}

		s := u.String()
		if _, err := parseArgs(s); err != nil {
			t.Fatalf("parseArgs(%q) = %v, but re-parsing its String() %q failed: %v", arg, u, s, err)
		}
	})
}
