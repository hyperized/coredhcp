// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package logger

import (
	"io"
	"testing"
)

// discardConsole swaps out.console for io.Discard for the duration of the
// benchmark, so the timed loop measures formatting rather than terminal
// I/O, and restores the previous writer once the benchmark ends.
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

// BenchmarkLoggerPrintf measures the printf-style logging path: format,
// slog attribute construction, and text-handler encoding.
func BenchmarkLoggerPrintf(b *testing.B) {
	b.ReportAllocs()
	discardConsole(b)

	l := GetLogger("bench")

	for b.Loop() {
		l.Printf("lease for %s expires in %d seconds", "aa:bb:cc:dd:ee:ff", 3600)
	}
}

// BenchmarkLoggerWith measures attaching structured context via With before
// logging a line, the pattern plugins use to tag messages per request.
func BenchmarkLoggerWith(b *testing.B) {
	b.ReportAllocs()
	discardConsole(b)

	l := GetLogger("bench")

	for b.Loop() {
		l.With("mac", "aa:bb:cc:dd:ee:ff", "iface", "eth0").Info("lease assigned")
	}
}
