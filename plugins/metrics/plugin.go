// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package metrics implements a plugin that counts DHCP traffic and serves the
// counters over HTTP in the Prometheus text exposition format.
//
// The exposition is written by hand instead of through the Prometheus client
// library. All this plugin needs is two monotonic counters and one static
// gauge, and the text format for those is a handful of Fprintf calls; the
// client library would pull a dependency subtree into a fork that keeps its
// go.mod deliberately short.
//
// The one thing to know before reading the rest: the listener lives in a
// package-level registry (see registry). setup4 and setup6 are called
// independently, once per server section in config.yml, but operators expect a
// single scrape endpoint covering both families. The registry is what lets the
// two calls share one listener and one set of counters.
//
// # Where it may listen
//
// A unix socket or a loopback port, and nothing else. The rules are shared
// with the leaseapi plugin through the endpoint package: an exposition says
// how much traffic the server sees and of what kind, and there is no
// authentication to put in front of it. An operator who wants the endpoint
// reachable from elsewhere puts a reverse proxy in front of it and
// authenticates there, or lets the scraper read the unix socket.
package metrics

import (
	"bytes"
	"context"
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
	"github.com/coredhcp/coredhcp/plugins/internal/endpoint"
)

var log = logger.GetLogger("plugins/metrics")

// pluginName is what the plugin is called in config.yml and what every error
// this package returns is prefixed with.
const pluginName = "metrics"

// Plugin wraps the metrics plugin information.
//
// The plugin takes the address its HTTP listener binds to, and for a unix
// socket an optional mode:
//
//	server4:
//	  plugins:
//	    - metrics: 127.0.0.1:9754
//	    - metrics: tcp:127.0.0.1:9754
//	    - metrics: unix:/run/coredhcp/metrics.sock mode:0660
//
// The bare host:port is the form this plugin has always taken and means what
// the tcp: one means. The host has to be a loopback address either way, so a
// configuration that binds the wildcard address finds out at startup rather
// than by being scraped from the next subnet over.
//
// Both handlers only count and hand the response straight on, so list
// `metrics` first in each plugin section. Any plugin ahead of it that stops the
// chain hides those requests from the counters entirely.
//
// When server4 and server6 both configure the plugin with the same address,
// one listener serves both. A second address while one is already bound is a
// setup error: there is a single set of counters, so a second endpoint would
// only duplicate the first.
var Plugin = plugins.Plugin{
	Name:   pluginName,
	Setup6: setup6,
	Setup4: setup4,
}

const (
	// metricBuildInfo and metricRequests are the two exposed metric names.
	metricBuildInfo = "coredhcp_build_info"
	metricRequests  = "coredhcp_requests_total"

	// family4 and family6 are the values of the "family" label.
	family4 = "4"
	family6 = "6"

	// typeUnknown labels a request whose message type could not be read at
	// all, as opposed to one carrying a type this dhcp library has no name
	// for: those keep the library's rendering, e.g. "unknown_(42)".
	typeUnknown = "unknown"

	// contentType is the Prometheus text format version this plugin emits.
	contentType = "text/plain; version=0.0.4; charset=utf-8"

	// Timeouts for the scrape endpoint. A scrape is a sub-millisecond
	// request against a local buffer, so these only exist to keep a stuck or
	// hostile client from holding a connection open indefinitely.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

// registry maps a configured listen address to the collector serving it.
//
// This is deliberately package-level shared state. Plugin setup functions
// receive nothing but their arguments and there is no object server4 and
// server6 setup could otherwise share, yet both families have to end up in one
// exposition. Keying by the configured address string makes the second setup
// on the same address a no-op returning the collector the first one started.
//
// mu guards the map. The counters inside a collector do their own
// synchronisation, so a scrape never blocks a setup and vice versa.
var registry = struct {
	mu        sync.Mutex
	listeners map[string]*collector
}{listeners: make(map[string]*collector)}

// requestKey identifies one coredhcp_requests_total series.
type requestKey struct {
	family  string
	msgType string
}

// collector holds the counters behind one HTTP listener and serves them.
//
// collector is safe for concurrent use. requests is guarded by mu, and its
// values are pointers so incrementing a series that already exists needs only
// the read lock plus one atomic add: every handler goroutine the server spawns
// per packet hits that path.
type collector struct {
	srv *http.Server
	ln  net.Listener
	// done is closed when the serve goroutine returns. Nothing in production
	// waits on it; tests do, so they can tear a listener down without sleeping.
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

// setup validates the plugin arguments and returns the collector to count into,
// starting the HTTP listener if this is the first setup for that address.
func setup(args []string) (*collector, error) {
	// AllowBareTCP keeps every configuration written before a scheme was an
	// option working: "127.0.0.1:9754" is read as a tcp address. The
	// loopback rule applies to it all the same.
	e, err := endpoint.Parse(pluginName, args, endpoint.AllowBareTCP())
	if err != nil {
		return nil, err
	}
	return obtain(e)
}

// obtain returns the collector for e, starting a listener the first time the
// address is seen.
//
// One address per process is the whole contract: a second server section either
// names the same address, and shares the listener, or the configuration asks
// for two endpoints over one set of counters, which is a mistake worth failing
// on at startup rather than resolving silently.
func obtain(e endpoint.Endpoint) (*collector, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	key := e.Key()
	if c, ok := registry.listeners[key]; ok {
		return c, nil
	}
	for running := range registry.listeners {
		// The map holds at most one entry, so this loop reads the address
		// already bound and returns; see the doc comment above.
		return nil, fmt.Errorf("%s: already listening on %s, refusing to also listen on %s", pluginName, running, key)
	}
	c, err := newCollector(e)
	if err != nil {
		return nil, err
	}
	registry.listeners[key] = c
	return c, nil
}

// newCollector binds e and starts serving the exposition on it.
func newCollector(e endpoint.Endpoint) (*collector, error) {
	c := &collector{
		done:     make(chan struct{}),
		requests: make(map[requestKey]*atomic.Uint64),
	}

	mux := http.NewServeMux()
	// The method and path filtering is the ServeMux pattern's job (Go 1.22+):
	// any other path gets a 404, /metrics with any other method a 405.
	mux.HandleFunc("GET /metrics", c.serveMetrics)
	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Bind synchronously so an occupied port fails the setup and the server
	// refuses to start, rather than logging into the void a second later.
	//
	// The context is Background because there is nothing else to pass: a
	// setup function takes its arguments and nothing more, and the
	// context-aware form of it changes what the handler is given, not what
	// setup is. Listen puts its own deadline on top, so a bind that cannot
	// finish fails the startup instead of holding it.
	ln, err := e.Listen(context.Background())
	if err != nil {
		return nil, err
	}
	c.ln = ln

	// Serving is asynchronous: setup has to return a handler, not block.
	//
	// The server is never stopped. Plugin setup in this fork runs once at
	// startup and the handlers it returns live for the lifetime of the
	// process, so there is no teardown hook to hang a Shutdown call on -
	// process exit is the only shutdown path there is.
	go func() {
		defer close(c.done)
		if err := c.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("metrics listener on %s stopped: %v", e.Key(), err)
		}
	}()
	// The bound address rather than the configured one: port 0 resolves to
	// whatever the kernel handed out, and that is the number an operator has
	// to point a scraper at.
	log.Infof("serving metrics on %s:%s at /metrics (%s)", ln.Addr().Network(), ln.Addr(), e.Guard())
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

// msgType6 returns the "type" label for a DHCPv6 request.
//
// Relayed requests are decapsulated first: counting the outer type would label
// every client behind a relay as RELAY-FORWARD and lose the distribution that
// makes the metric worth scraping. A packet that will not decapsulate is still
// counted, as typeUnknown, because dropping it would hide precisely the
// malformed traffic an operator went looking for.
func msgType6(req dhcpv6.DHCPv6) string {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Debugf("could not decapsulate relayed message, counting as %q: %v", typeUnknown, err)
		return typeUnknown
	}
	return sanitizeLabelValue(msg.Type().String())
}

// count increments the counter for one family and message type, creating the
// series the first time that combination is seen.
//
// Series count is bounded: two families times the 256 strings a message-type
// byte can render as, unknown types included. A client cannot grow the map
// past that.
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

// series returns the counter for k, creating it unless another goroutine won
// the race between count dropping the read lock and this taking the write one.
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

// serveMetrics answers a scrape.
func (c *collector) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	body := c.expose()
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(body); err != nil {
		// A scraper hanging up mid-body is its own problem, but a flapping
		// Prometheus is worth a line when someone turns debug logging on.
		log.Debugf("writing metrics response: %v", err)
	}
}

// expose renders the current state of every metric.
//
// The output is deterministic: the series are sorted, so two scrapes differ
// only where the counters differ.
func (c *collector) expose() []byte {
	var buf bytes.Buffer
	// A scrape is a few dozen short lines. Pre-size for that rather than
	// pooling buffers for an endpoint hit once every scrape interval.
	buf.Grow(512)

	fmt.Fprintf(&buf, "# HELP %s Version information about the running coredhcp binary.\n", metricBuildInfo)
	fmt.Fprintf(&buf, "# TYPE %s gauge\n", metricBuildInfo)
	fmt.Fprintf(&buf, "%s{goversion=\"%s\"} 1\n", metricBuildInfo, sanitizeLabelValue(runtime.Version()))

	// HELP and TYPE are emitted even with no samples yet, so a scrape taken
	// before the first packet still tells the operator the metric exists.
	fmt.Fprintf(&buf, "# HELP %s Number of DHCP requests received, by IP family and message type.\n", metricRequests)
	fmt.Fprintf(&buf, "# TYPE %s counter\n", metricRequests)
	for _, line := range c.requestLines() {
		buf.WriteString(line)
	}
	return buf.Bytes()
}

// requestLines renders one sample line per series, sorted.
//
// Sorting the rendered lines is enough to order by family then message type:
// every line shares the metric name and label-name prefix, so lexical order on
// the whole line is lexical order on the label values.
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

// labelSanitizer normalises a label value: spaces to underscores, because both
// dhcpv4 and dhcpv6 render an unrecognised message type as "unknown (42)", plus
// the three characters the text format requires to be escaped inside a quoted
// value.
var labelSanitizer = strings.NewReplacer(
	" ", "_",
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
)

// sanitizeLabelValue returns s ready to be placed between the quotes of a label
// value, lowercased.
//
// Every message-type string the dhcp library returns today is plain ASCII; the
// escaping is here so that a name added upstream with a quote or a backslash in
// it cannot produce an exposition body Prometheus refuses to parse.
func sanitizeLabelValue(s string) string {
	return labelSanitizer.Replace(strings.ToLower(s))
}
