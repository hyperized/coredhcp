// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package logger

import (
	"io"
	"testing"
)

// discardConsole swaps out.console for io.Discard so the timed loop measures
// formatting, not terminal I/O.
func discardConsole(b *testing.B) {
	b.Helper()

	out.mu.Lock()
	prev := out.console
	out.console = io.Discard
	out.mu.Unlock()

	b.Cleanup(func() {
		out.mu.Lock()
		out.console = prev
		out.mu.Unlock()
	})
}

// Measures the printf path: formatting, slog attribute construction, and text-handler encoding.
func BenchmarkLoggerPrintf(b *testing.B) {
	b.ReportAllocs()
	discardConsole(b)

	l := GetLogger("bench")

	for b.Loop() {
		l.Printf("lease for %s expires in %d seconds", "aa:bb:cc:dd:ee:ff", 3600)
	}
}

// The pattern plugins use to tag messages per request.
func BenchmarkLoggerWith(b *testing.B) {
	b.ReportAllocs()
	discardConsole(b)

	l := GetLogger("bench")

	for b.Loop() {
		l.With("mac", "aa:bb:cc:dd:ee:ff", "iface", "eth0").Info("lease assigned")
	}
}
