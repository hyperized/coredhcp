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
	// GOMAXPROCS. Above one per core because a plugin can block on Redis,
	// NetBox or DNS halfway down the chain; not far above it because each
	// handler holds a 64 KiB buffer out of bufpool and, for a layer-2
	// reply, an AF_PACKET descriptor (see sendEthernet).
	inFlightPerCPU = 8

	// defaultDrainTimeout bounds how long Close waits for the handlers that
	// are still running: long enough for a plugin's round trip to finish,
	// short enough that a service manager's kill timeout is never reached.
	defaultDrainTimeout = 5 * time.Second

	logInterval = time.Second
)

// reason names why a datagram was thrown away before the plugin chain saw
// it. The set is fixed, so the counters and the log limiter can be arrays
// indexed by it.
type reason int

const (
	reasonOverload reason = iota
	reasonShutdown
	// reasonRelayed is a relayed request in a family whose chain holds no
	// relay plugin to say which relays the server answers.
	reasonRelayed
	numReasons
)

var reasonText = [numReasons]string{
	reasonOverload: "in-flight handler limit reached",
	reasonShutdown: "server is shutting down",
	reasonRelayed:  "relayed request and no relay plugin configured",
}

// reasonAdvice is what the operator should do about a drop, or what it means
// when there is nothing to do. It rides along with reasonText in the log line
// dropped writes.
var reasonAdvice = [numReasons]string{
	reasonOverload: "clients will retry, look for a plugin that blocks on the network such as redis, netbox or ddns",
	reasonShutdown: "nothing to do, the shutdown discards what arrives after it began",
	reasonRelayed:  "add `relay: allow <address|prefix> ...` to the family's plugin list, naming the relays this server answers",
}

func (r reason) String() string { return reasonText[r] }

// Drops counts the datagrams a server threw away before any plugin saw them.
// The counts run from Start and are never reset.
//
// Overload and ShuttingDown never reach an events.Observer, since the
// datagram was never parsed. Relayed does, as an events.Request with
// events.OutcomeDropped.
type Drops struct {
	// Overload is datagrams dropped because the in-flight handler limit was
	// reached, see WithMaxInFlight.
	Overload uint64
	// ShuttingDown is datagrams read after Close began, dropped so no reply
	// is written to a socket that is about to close.
	ShuttingDown uint64
	// Relayed is relayed requests dropped because the family's plugin chain
	// has no relay plugin: a non-zero giaddr on DHCPv4, a Relay-forward on
	// DHCPv6.
	Relayed uint64
}

// gate stands between the read loops and the handler goroutines.
//
// A gate is safe for concurrent use by every listener's read loop and by
// Close at the same time. A nil *gate counts nothing and has nothing to
// wait for, which is what a server built without one (only a test double)
// gets; run is the exception and needs a real gate, which is why Serve
// builds one for a listener that arrived without.
type gate struct {
	// sem is the in-flight limit, a buffered channel rather than a counter
	// so a read loop can try for a slot and give up in one non-blocking
	// select.
	sem chan struct{}

	// mu orders closed against the WaitGroup. Once stop has returned, no
	// further handler can join wg, which is what makes waiting on it mean
	// anything.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	counts [numReasons]atomic.Uint64

	// logMu guards logged, the last time each reason produced a line.
	logMu  sync.Mutex
	logged [numReasons]time.Time

	// now is a field so the rate-limit test can step over the interval
	// instead of sleeping through it.
	now func() time.Time
}

// defaultMaxInFlight reads GOMAXPROCS once, at startup: a server whose
// processor allowance changes under it keeps the limit it was built with.
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

// run starts fn on its own goroutine and reports whether it did. It refuses
// when the gate is full and once the server is shutting down; the datagram
// is then gone, which is the right answer for DHCP, since a client
// retransmits and queueing would cost memory the server cannot bound.
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
// started at all.
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

// stop closes the gate. Once it returns, the set of handlers a shutdown has
// to wait for cannot grow.
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
// The goroutine parked on the WaitGroup outlives a timeout, which is the
// point of it: the handler it waits for is stuck somewhere in a plugin, and
// it ends when that handler does.
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
// of log lines.
func (g *gate) dropped(r reason) {
	if g == nil {
		return
	}
	n := g.counts[r].Add(1)
	if !g.allowLog(r) {
		return
	}
	log.Warningf("dropping datagram (%s), %d so far; %s", r, n, reasonAdvice[r])
}

// allowLog reports whether r may log now, and records the time when it may.
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
