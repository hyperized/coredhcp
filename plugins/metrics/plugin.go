// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package metrics implements a plugin that counts DHCP traffic and serves the
// counters over HTTP in the Prometheus text exposition format.
//
// The exposition is written by hand rather than through the Prometheus client
// library: two counters and one gauge are a handful of Fprintf calls, and the
// library would pull a dependency subtree into a deliberately short go.mod.
//
// setup4 and setup6 are called independently, once per server section, but
// operators expect one scrape endpoint covering both families. A package-level
// registry is what lets the two calls share a listener and a set of counters.
package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/metrics")

// Plugin wraps the metrics plugin information.
//
// The plugin takes one argument, the address its HTTP listener binds to:
//
//	server4:
//	  plugins:
//	    - metrics: 127.0.0.1:9754
//
// List it first in each plugin section: any plugin ahead of it that stops the
// chain hides those requests from the counters. Both server sections may name
// the same address and share one listener; a second address is a setup error,
// since a second endpoint would only duplicate the one set of counters.
var Plugin = plugins.Plugin{
	Name:   "metrics",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	metricBuildInfo = "coredhcp_build_info"
	metricRequests  = "coredhcp_requests_total"

	family4 = "4"
	family6 = "6"

	// A message type that could not be read at all, as opposed to one the dhcp
	// library has no name for: those keep its rendering, e.g. "unknown_(42)".
	typeUnknown = "unknown"

	contentType = "text/plain; version=0.0.4; charset=utf-8"

	// A scrape is a sub-millisecond request against a local buffer, so these
	// only stop a stuck or hostile client holding a connection open.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

// Package-level because setup functions receive nothing but their arguments,
// yet both families have to end up in one exposition. mu guards the map only;
// a collector's counters synchronise themselves, so a scrape never blocks a
// setup.
var registry = struct {
	mu        sync.Mutex
	listeners map[string]*collector
}{listeners: make(map[string]*collector)}

type requestKey struct {
	family  string
	msgType string
}

// Safe for concurrent use. The map values are pointers, so incrementing an
// existing series takes only the read lock plus one atomic add -- the path
// every per-packet handler goroutine hits.
type collector struct {
	srv *http.Server
	ln  net.Listener
	// Nothing in production waits on this; tests do, so they can tear a
	// listener down without sleeping.
	done chan struct{}

	mu       sync.RWMutex
	requests map[requestKey]*atomic.Uint64
}

func setup4(args ...string) (handler.Handler4, error) {
	c, err := setup(args)
	if err != nil {
		return nil, err
	}
	log.Printf("loaded plugin for DHCPv4.")
	return c.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	c, err := setup(args)
	if err != nil {
		return nil, err
	}
	log.Printf("loaded plugin for DHCPv6.")
	return c.Handler6, nil
}

func setup(args []string) (*collector, error) {
	addr, err := listenAddr(args)
	if err != nil {
		return nil, err
	}
	return obtain(addr)
}

// The syntax check is not redundant with the bind that follows: it names the
// offending argument, where net.Listen reports what reads like a network fault.
func listenAddr(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("metrics: expected exactly one argument, a listen address, got %d", len(args))
	}
	addr := strings.TrimSpace(args[0])
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("metrics: invalid listen address %q: %w", addr, err)
	}
	return addr, nil
}

// One address per process: a second server section either names the same one
// and shares the listener, or asks for two endpoints over one set of counters,
// which is worth failing on at startup rather than resolving silently.
func obtain(addr string) (*collector, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if c, ok := registry.listeners[addr]; ok {
		return c, nil
	}
	for running := range registry.listeners {
		// The map holds at most one entry, so this reads the bound address.
		return nil, fmt.Errorf("metrics: already listening on %s, refusing to also listen on %s", running, addr)
	}
	c, err := newCollector(addr)
	if err != nil {
		return nil, err
	}
	registry.listeners[addr] = c
	return c, nil
}

func newCollector(addr string) (*collector, error) {
	c := &collector{
		done:     make(chan struct{}),
		requests: make(map[requestKey]*atomic.Uint64),
	}

	mux := http.NewServeMux()
	// The pattern does the method and path filtering: any other path gets a
	// 404, /metrics with any other method a 405.
	mux.HandleFunc("GET /metrics", c.serveMetrics)
	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Bind synchronously so an occupied port fails setup, rather than logging
	// into the void a second later.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics: cannot listen on %s: %w", addr, err)
	}
	c.ln = ln

	// Setup has to return a handler, not block. The server is never stopped:
	// there is no teardown hook to hang a Shutdown call on, and process exit
	// is the only shutdown path there is.
	go func() {
		defer close(c.done)
		if err := c.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("metrics listener on %s stopped: %v", addr, err)
		}
	}()
	log.Infof("serving metrics on http://%s/metrics", ln.Addr())
	return c, nil
}

// Handler4 counts a DHCPv4 request and returns the response untouched.
func (c *collector) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	c.count(family4, sanitizeLabelValue(req.MessageType().String()))
	return resp, false
}

// Handler6 counts a DHCPv6 request and returns the response untouched.
func (c *collector) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	c.count(family6, msgType6(req))
	return resp, false
}

// Relayed requests are decapsulated first, or every client behind a relay
// would count as RELAY-FORWARD. One that will not decapsulate still counts, as
// typeUnknown: dropping it would hide the traffic an operator came looking for.
func msgType6(req dhcpv6.DHCPv6) string {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Debugf("could not decapsulate relayed message, counting as %q: %v", typeUnknown, err)
		return typeUnknown
	}
	return sanitizeLabelValue(msg.Type().String())
}

// Series count is bounded at two families times the 256 strings a message-type
// byte can render as, so a client cannot grow the map without limit.
func (c *collector) count(family, msgType string) {
	k := requestKey{family: family, msgType: msgType}
	c.mu.RLock()
	ctr, ok := c.requests[k]
	c.mu.RUnlock()
	if !ok {
		ctr = c.series(k)
	}
	ctr.Add(1)
}

// Rechecks under the write lock: another goroutine may have won the race since
// count dropped the read lock.
func (c *collector) series(k requestKey) *atomic.Uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok := c.requests[k]; ok {
		return ctr
	}
	ctr := &atomic.Uint64{}
	c.requests[k] = ctr
	return ctr
}

func (c *collector) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	body := c.expose()
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(body); err != nil {
		// A scraper hanging up mid-body is its own problem, but a flapping
		// Prometheus is worth a line at debug level.
		log.Debugf("writing metrics response: %v", err)
	}
}

// The series are sorted, so two scrapes differ only where the counters do.
func (c *collector) expose() []byte {
	var buf bytes.Buffer
	// A few dozen short lines; not worth pooling buffers for an endpoint hit
	// once a scrape interval.
	buf.Grow(512)

	fmt.Fprintf(&buf, "# HELP %s Version information about the running coredhcp binary.\n", metricBuildInfo)
	fmt.Fprintf(&buf, "# TYPE %s gauge\n", metricBuildInfo)
	fmt.Fprintf(&buf, "%s{goversion=\"%s\"} 1\n", metricBuildInfo, sanitizeLabelValue(runtime.Version()))

	// Emitted even with no samples, so a scrape before the first packet still
	// tells the operator the metric exists.
	fmt.Fprintf(&buf, "# HELP %s Number of DHCP requests received, by IP family and message type.\n", metricRequests)
	fmt.Fprintf(&buf, "# TYPE %s counter\n", metricRequests)
	for _, line := range c.requestLines() {
		buf.WriteString(line)
	}
	return buf.Bytes()
}

// Sorting the rendered lines orders by family then message type: every line
// shares the metric name and label-name prefix.
func (c *collector) requestLines() []string {
	c.mu.RLock()
	lines := make([]string, 0, len(c.requests))
	for k, ctr := range c.requests {
		lines = append(lines, fmt.Sprintf("%s{family=\"%s\",type=\"%s\"} %d\n",
			metricRequests, k.family, k.msgType, ctr.Load()))
	}
	c.mu.RUnlock()
	slices.Sort(lines)
	return lines
}

// Spaces become underscores because both dhcpv4 and dhcpv6 render an
// unrecognised message type as "unknown (42)"; the rest is the escaping the
// text format requires inside a quoted value.
var labelSanitizer = strings.NewReplacer(
	" ", "_",
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
)

// The escaping guards against a message-type name added upstream with a quote
// or backslash in it producing a body Prometheus refuses to parse.
func sanitizeLabelValue(s string) string {
	return labelSanitizer.Replace(strings.ToLower(s))
}
