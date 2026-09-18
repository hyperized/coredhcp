// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package server

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// inFlightPerCPU is how many handlers the default limit allows per
	// GOMAXPROCS.
	//
	// A handler is mostly processor work: parse, walk the chain, write the
	// reply. It is not only that, because a plugin can go to Redis, to
	// NetBox or to a DNS server halfway down the chain, and the processor
	// is free for the next packet while it waits. One handler per core
	// would idle the machine on every such wait, so the limit sits above
	// the core count. It does not sit far above it: each handler in flight
	// holds a 64 KiB buffer out of bufpool, and a DHCPv4 reply to a client
	// that has no address yet holds an AF_PACKET descriptor for as long as
	// it takes to serialise and send (see sendEthernet). Eight per core is
	// 4 MiB of buffers and at most 64 descriptors on an eight-core machine,
	// both well inside the usual limits, and it still absorbs bursts two
	// orders of magnitude above what a DHCP segment produces.
	inFlightPerCPU = 8

	// defaultDrainTimeout bounds how long Close waits for the handlers that
	// are still running. Long enough for a plugin in the middle of a Redis
	// round trip or a DNS update to finish, short enough that a service
	// manager killing the process at 90 seconds is never what stops it.
	defaultDrainTimeout = 5 * time.Second

	// logInterval is how often one drop reason may produce a log line.
	logInterval = time.Second
)

// reason names why a datagram was thrown away before the plugin chain saw
// it. The set is fixed and small, which is what keeps the counters and the
// log limiter bounded by the number of reasons rather than by the traffic
// they describe.
type reason int

const (
	// reasonOverload is the in-flight limit: the handlers already running
	// fill the gate, so this datagram gets no goroutine.
	reasonOverload reason = iota
	// reasonShutdown is a datagram read after Close began.
	reasonShutdown
	// reasonRelayed is a relayed request in a family whose chain holds no
	// relay plugin, so nothing says which relays the server answers.
	reasonRelayed
	numReasons
)

// reasonText explains each drop in the log line, indexed by the reason.
var reasonText = [numReasons]string{
	reasonOverload: "in-flight handler limit reached",
	reasonShutdown: "server is shutting down",
	reasonRelayed:  "relayed request and no relay plugin configured",
}

// String is the explanation an operator reads in the log.
func (r reason) String() string { return reasonText[r] }

// Drops counts the datagrams a server threw away before any plugin saw them.
// The counts run from Start and are never reset.
//
// Overload and ShuttingDown never reach an events.Observer: the datagram was
// not parsed, so there is nothing to report about it beyond that it is gone.
// Relayed does produce an events.Request with events.OutcomeDropped, because
// by then the request has been read.
type Drops struct {
	// Overload is datagrams dropped because the in-flight handler limit was
	// reached. See WithMaxInFlight.
	Overload uint64
	// ShuttingDown is datagrams read after Close began. They are dropped so
	// no reply is written to a socket that is about to close.
	ShuttingDown uint64
	// Relayed is relayed requests dropped because the family's plugin chain
	// has no relay plugin: a non-zero giaddr on DHCPv4, a Relay-forward on
	// DHCPv6.
	Relayed uint64
}

// gate stands between the read loops and the handler goroutines. It bounds
// how many handlers run at once, lets a shutdown wait for the ones that are
// running, and counts and logs what it turned away.
//
// A gate is safe for concurrent use by every listener's read loop and by
// Close at the same time. A nil *gate belongs to a server that was built
// without one, which only a test double does: it counts nothing and has
// nothing to wait for. run is the exception and needs a real gate, which is
// why Serve builds one for a listener that arrived without.
type gate struct {
	// sem is the in-flight limit: one slot per running handler, given back
	// when the handler returns. A buffered channel rather than a counter,
	// so a read loop can try for a slot and give up in one non-blocking
	// select.
	sem chan struct{}

	// mu orders closed against the WaitGroup. Once stop has returned, no
	// further handler can join wg, which is what makes waiting on it mean
	// anything.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	// counts is one counter per reason, read back through Servers.Drops.
	counts [numReasons]atomic.Uint64

	// logMu guards logged, the last time each reason produced a line.
	logMu  sync.Mutex
	logged [numReasons]time.Time

	// now reads the clock. It is a field so the rate-limit test can step
	// over the interval instead of sleeping through it.
	now func() time.Time
}

// defaultMaxInFlight is the limit a server uses when the caller named none.
// GOMAXPROCS is read once, at startup: a server whose processor allowance
// changes under it keeps the limit it was built with.
func defaultMaxInFlight() int {
	return inFlightPerCPU * runtime.GOMAXPROCS(0)
}

// newGate returns a gate that allows maxInFlight handlers at once, or the
// default when maxInFlight is not a usable number.
func newGate(maxInFlight int) *gate {
	if maxInFlight < 1 {
		maxInFlight = defaultMaxInFlight()
	}
	return &gate{sem: make(chan struct{}, maxInFlight), now: time.Now}
}

// run starts fn on its own goroutine and reports whether it did.
//
// It refuses in two cases: the gate is full, and the server is shutting
// down. Either way the datagram is gone, which is the right answer for DHCP.
// A client retransmits, so a shed packet costs a retry, while queueing it
// would cost memory the server does not get to bound.
func (g *gate) run(fn func()) bool {
	select {
	case g.sem <- struct{}{}:
	default:
		g.dropped(reasonOverload)
		return false
	}
	if !g.track(fn) {
		<-g.sem
		g.dropped(reasonShutdown)
		return false
	}
	return true
}

// track starts fn under the lock that orders it against stop, so a handler
// is either on the WaitGroup before a shutdown starts waiting or never
// started at all. fn gives its slot back when it returns.
func (g *gate) track(fn func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.wg.Go(func() {
		defer func() { <-g.sem }()
		fn()
	})
	return true
}

// stop closes the gate. From the moment it returns, run refuses every
// datagram and the set of handlers a shutdown has to wait for cannot grow.
func (g *gate) stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
}

// wait blocks until every handler that was started has returned, or until
// timeout elapses, and reports whether they all finished. timeout has to be
// positive; the server's own value is defaulted in Start.
//
// The goroutine parked on the WaitGroup outlives a timeout, and that is the
// point of the timeout: the handler it waits for is stuck somewhere in a
// plugin and the caller has stopped waiting for it. It ends when that
// handler does.
func (g *gate) wait(timeout time.Duration) bool {
	if g == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// dropped counts one datagram thrown away for r, and logs it at most once
// per reason per logInterval so a flood of drops does not turn into a flood
// of log lines. The count is what a caller reads back, the line is what an
// operator sees.
func (g *gate) dropped(r reason) {
	if g == nil {
		return
	}
	n := g.counts[r].Add(1)
	if !g.allowLog(r) {
		return
	}
	log.Warningf("dropping datagram (%s), %d so far", r, n)
}

// allowLog reports whether r may produce a line now, and records the time
// when it may.
func (g *gate) allowLog(r reason) bool {
	g.logMu.Lock()
	defer g.logMu.Unlock()
	t := g.now()
	if prev := g.logged[r]; !prev.IsZero() && t.Sub(prev) < logInterval {
		return false
	}
	g.logged[r] = t
	return true
}

// drops reads the counters back.
func (g *gate) drops() Drops {
	if g == nil {
		return Drops{}
	}
	return Drops{
		Overload:     g.counts[reasonOverload].Load(),
		ShuttingDown: g.counts[reasonShutdown].Load(),
		Relayed:      g.counts[reasonRelayed].Load(),
	}
}
