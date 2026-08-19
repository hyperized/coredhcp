// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp

import (
	"strings"
	"testing"
)

// FuzzParseArgs feeds arbitrary strings to parseArgs (wrapped as the single
// argument it requires - the argument-count validation itself is already
// covered by TestParseArgs). The invariant: never panic, and on success the
// result is a *url.URL that url.Parse itself considers well-formed enough to
// round-trip through String() and be re-parsed without error.
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
		// Found by fuzzing: url.Parse accepts an IPv6 host with a
		// percent-escaped zone ID ("%25" = escaped '%') even when the zone
		// ID itself is raw, invalid UTF-8 (here \xf1) - but u.String()
		// re-escapes that same zone ID into a form url.Parse then rejects
		// ("invalid URL escape"). That is a round-trip gap in net/url's own
		// IPv6-zone handling, not in parseArgs, which does nothing but call
		// url.Parse/u.String() - see the skip below.
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
			// url.Parse stores an IPv6 zone ID's escaped '%25' back as a
			// literal '%' in u.Host, so this is the decoded form of the
			// same zone-ID case: net/url's own String()/Parse round trip
			// is not guaranteed here (see the seed comment above).
			return
		}

		s := u.String()
		if _, err := parseArgs(s); err != nil {
			t.Fatalf("parseArgs(%q) = %v, but re-parsing its String() %q failed: %v", arg, u, s, err)
		}
	})
}
