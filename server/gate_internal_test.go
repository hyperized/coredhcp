// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/logger"
)

// syncBuffer is a log sink a test can read while the read loops are still
// writing to it from their own goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) count(s string) int {
	return strings.Count(b.String(), s)
}

// captureLog redirects the shared logger to a buffer for the test. The
// console writer is process-wide, so a test using this may not run in
// parallel with another one that logs.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	logger.WithConsole(buf)
	t.Cleanup(func() { logger.WithConsole(os.Stderr) })
	return buf
}

// fakeClock lets a test drive the drop limiter over its interval without
// sleeping through it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func blockingFn() (fn func(), release func(), done chan struct{}) {
	hold := make(chan struct{})
	done = make(chan struct{})
	return func() {
			<-hold
			close(done)
		}, sync.OnceFunc(func() {
			close(hold)
		}), done
}

func TestNewGateSizesTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		max  int
		want int
	}{
		{name: "explicit limit", max: 3, want: 3},
		{name: "zero takes the default", max: 0, want: defaultMaxInFlight()},
		{name: "negative takes the default", max: -7, want: defaultMaxInFlight()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cap(newGate(tc.max).sem))
		})
	}
}

func TestDefaultMaxInFlight(t *testing.T) {
	assert.Equal(t, inFlightPerCPU*runtime.GOMAXPROCS(0), defaultMaxInFlight())
}

func TestGateDropsWhenFull(t *testing.T) {
	captureLog(t)
	g := newGate(2)

	first, releaseFirst, firstDone := blockingFn()
	second, releaseSecond, secondDone := blockingFn()
	require.True(t, g.run(first))
	require.True(t, g.run(second))

	var ran bool
	assert.False(t, g.run(func() { ran = true }), "the gate is full, the third handler must not start")
	assert.False(t, ran)
	assert.Equal(t, Drops{Overload: 1}, g.drops())

	releaseFirst()
	<-firstDone
	releaseSecond()
	<-secondDone
	assert.True(t, g.wait(time.Minute))
	assert.True(t, g.run(func() {}))
	assert.True(t, g.wait(time.Minute))
	assert.Equal(t, Drops{Overload: 1}, g.drops())
}

// A stopped gate gives back the slot it took, or a shutdown is left waiting
// on a handler that never ran.
func TestGateRefusesAfterStop(t *testing.T) {
	captureLog(t)
	g := newGate(1)
	g.stop()

	var ran bool
	assert.False(t, g.run(func() { ran = true }))
	assert.False(t, ran)
	assert.Empty(t, g.sem, "the slot has to go back, or the gate stays full for good")
	assert.Equal(t, Drops{ShuttingDown: 1}, g.drops())
	assert.True(t, g.wait(time.Minute))
}

func TestGateWaitReturnsWhenHandlersFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGate(4)
		fn, release, done := blockingFn()
		require.True(t, g.run(fn))

		waited := make(chan bool, 1)
		go func() { waited <- g.wait(time.Minute) }()

		synctest.Wait()
		assert.Empty(t, waited, "wait must not return while a handler is still running")

		release()
		<-done
		assert.True(t, <-waited)
	})
}

func TestGateWaitGivesUpAtTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGate(4)
		fn, release, done := blockingFn()
		require.True(t, g.run(fn))

		start := time.Now()
		assert.False(t, g.wait(50*time.Millisecond))
		assert.Equal(t, 50*time.Millisecond, time.Since(start))

		// Let the stuck handler go, so the goroutine parked on the WaitGroup
		// ends with it.
		release()
		<-done
		assert.True(t, g.wait(time.Minute))
	})
}

func TestGateLogsOneLinePerReasonPerInterval(t *testing.T) {
	buf := captureLog(t)
	clk := &fakeClock{t: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)}
	g := newGate(1)
	g.now = clk.now

	for range 5 {
		g.dropped(reasonOverload)
	}
	assert.Equal(t, 1, buf.count("in-flight handler limit reached"))

	g.dropped(reasonRelayed)
	assert.Equal(t, 1, buf.count("no relay plugin configured"))

	clk.advance(logInterval)
	g.dropped(reasonOverload)
	assert.Equal(t, 2, buf.count("in-flight handler limit reached"))
	assert.Equal(t, Drops{Overload: 6, Relayed: 1}, g.drops())
}

func TestGateLogsTheRunningCount(t *testing.T) {
	buf := captureLog(t)
	g := newGate(1)
	g.dropped(reasonShutdown)
	assert.Contains(t, buf.String(), "dropping datagram (server is shutting down), 1 so far")
}

func TestNilGateIsSafe(t *testing.T) {
	var g *gate
	assert.NotPanics(t, func() {
		g.stop()
		g.dropped(reasonOverload)
	})
	assert.True(t, g.wait(time.Minute))
	assert.Equal(t, Drops{}, g.drops())
}
