// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config_test

import (
	"testing"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/logger"
)

// Both server6 and server4 sections, as a typical deployment has.
func BenchmarkLoad(b *testing.B) {
	b.ReportAllocs()
	// Load logs a line per discovered plugin at the default Info level;
	// silencing the console isolates the parse cost from terminal I/O.
	logger.WithNoStdOutErr()

	for b.Loop() {
		if _, err := config.Load("testdata/valid_both.yml"); err != nil {
			b.Fatal(err)
		}
	}
}
