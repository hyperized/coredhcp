// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// scenario is one thing a plugin promises, and the exchange that proves it.
//
// plugin is the name as it appears in config.yaml, so a failure points at the
// line that configured the behaviour rather than at the test.
type scenario struct {
	plugin string
	name   string
	run    func(context.Context, *world) error
}

// result is what running a scenario produced.
type result struct {
	scenario
	err   error
	took  time.Duration
	notes []string
}

// runAll runs every scenario in order and returns the results.
//
// The scenarios are deliberately sequential and order dependent: a lease has
// to exist before the lease API can list it, and the pool-draining scenarios
// at the end leave the pool empty for the ones after them. A failure does
// not stop the run, because one broken plugin should not hide the state of
// the other twenty-eight.
func runAll(ctx context.Context, w *world, scenarios []scenario) []result {
	results := make([]result, 0, len(scenarios))
	for _, sc := range scenarios {
		if ctx.Err() != nil {
			results = append(results, result{scenario: sc, err: fmt.Errorf("not run: %w", ctx.Err())})
			continue
		}
		w.notes = w.notes[:0]
		started := time.Now()
		err := sc.run(ctx, w)
		results = append(results, result{
			scenario: sc,
			err:      err,
			took:     time.Since(started),
			notes:    append([]string(nil), w.notes...),
		})
	}
	return results
}

// writeReport prints one line per scenario and then the detail of every
// failure. Passing scenarios keep their notes out of the way; a failing one
// prints everything it saw, because that is the run someone is reading.
func writeReport(out io.Writer, results []result) int {
	const (
		pluginWidth = 14
		nameWidth   = 52
	)
	failed := 0

	_, _ = fmt.Fprintf(out, "\n%-*s %-*s %8s  %s\n", pluginWidth, "PLUGIN", nameWidth, "SCENARIO", "TIME", "RESULT")
	_, _ = fmt.Fprintln(out, strings.Repeat("-", pluginWidth+nameWidth+20))
	for _, r := range results {
		verdict := "PASS"
		if r.err != nil {
			verdict = "FAIL"
			failed++
		}
		_, _ = fmt.Fprintf(out, "%-*s %-*s %8s  %s\n",
			pluginWidth, r.plugin, nameWidth, truncate(r.name, nameWidth), r.took.Round(time.Millisecond), verdict)
	}

	if failed == 0 {
		_, _ = fmt.Fprintf(out, "\nexerciser: PASS, %d scenarios across %d plugins\n", len(results), countPlugins(results))
		return 0
	}

	_, _ = fmt.Fprintf(out, "\nexerciser: FAIL, %d of %d scenarios\n", failed, len(results))
	for _, r := range results {
		if r.err == nil {
			continue
		}
		_, _ = fmt.Fprintf(out, "\n  %s / %s\n    %v\n", r.plugin, r.name, r.err)
		for _, n := range r.notes {
			_, _ = fmt.Fprintf(out, "    note: %s\n", n)
		}
	}
	return 1
}

// countPlugins counts the distinct plugins the run covered.
func countPlugins(results []result) int {
	seen := make(map[string]struct{}, len(results))
	for _, r := range results {
		seen[r.plugin] = struct{}{}
	}
	return len(seen)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
