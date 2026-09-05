// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leaseapi serves the leases the server currently holds over a
// read-only HTTP API, on a unix socket or on loopback.
//
// Lease-holding plugins register themselves with the leases package during
// setup; this plugin serves whatever the registry currently reports on
// GET /v1/leases, /v1/pools and /v1/health, with family=4|6 and source=<name>
// filters on the first two.
//
//	server4:
//	  plugins:
//	    - leaseapi: unix:/run/coredhcp/api.sock mode:0660
//	    - leaseapi: tcp:127.0.0.1:9755
//
// # There is no authentication
//
// Socket permissions are the authentication (default mode 0600); a tcp
// address must be loopback. Put a reverse proxy or an ssh forward in front to
// expose this remotely. Never bind a routable address, which would publish
// every client's MAC, DUID, hostname and address to anyone who can reach it.
//
// The API is read-only: there is no endpoint that frees a lease or changes
// configuration, since that would need an authorisation model this has no
// way to provide.
//
// # Where it goes in the chain
//
// Anywhere: both handlers pass the response through untouched and never end
// the chain. Setup is what starts the listener; server4 and server6 sharing
// an address share one listener, since the registry is global.
package leaseapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/leaseapi")

// Plugin wraps the leaseapi plugin information.
var Plugin = plugins.Plugin{
	Name:   "leaseapi",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	// A request is a read of a few maps and a JSON encode, so these exist
	// only to keep a stuck or hostile client from holding a connection open.
	// writeTimeout is loosest since a large lease set streams out over it.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second

	// The net/http default, stated rather than inherited: this endpoint
	// answers a handful of fixed paths and has no use for large headers.
	maxHeaderBytes = 1 << 20
)

// Package-level shared state: setup functions receive nothing but their own
// arguments, so this is the only way server4 and server6 end up sharing a listener.
//
// mu guards the map only; serving a request never takes it.
var registry = struct {
	mu      sync.Mutex
	servers map[string]*server
}{servers: make(map[string]*server)}

// Holds no lease state of its own: every request reads the leases registry
// afresh, so an answer is as current as the moment it was asked for.
type server struct {
	srv *http.Server
	ln  net.Listener
	// Closed when the serve goroutine returns. Nothing in production waits
	// on it; tests do, so they can tear a listener down without sleeping.
	done chan struct{}
}

func setup4(args ...string) (handler.Handler4, error) {
	s, err := setup(args)
	if err != nil {
		return nil, err
	}
	log.Printf("loaded plugin for DHCPv4.")
	return s.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	s, err := setup(args)
	if err != nil {
		return nil, err
	}
	log.Printf("loaded plugin for DHCPv6.")
	return s.Handler6, nil
}

func setup(args []string) (*server, error) {
	e, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	return obtain(e)
}

// One address per process: a second server section either names the same
// address and shares the listener, or is a mistake worth failing on at
// startup rather than resolving silently.
func obtain(e endpoint) (*server, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	key := e.key()
	if s, ok := registry.servers[key]; ok {
		return s, nil
	}
	for running := range registry.servers {
		// The map holds at most one entry; this loop just reads that key.
		return nil, fmt.Errorf("leaseapi: already listening on %s, refusing to also listen on %s", running, key)
	}
	s, err := newServer(e)
	if err != nil {
		return nil, err
	}
	registry.servers[key] = s
	return s, nil
}

func newServer(e endpoint) (*server, error) {
	s := &server{done: make(chan struct{})}

	mux := http.NewServeMux()
	// ServeMux (Go 1.22+) handles the method/path filtering itself: a 404 or
	// 405 comes back as its own plain-text body, not JSON like the rest of this package.
	mux.HandleFunc("GET /v1/leases", serveLeases)
	mux.HandleFunc("GET /v1/pools", servePools)
	mux.HandleFunc("GET /v1/health", serveHealth)

	s.srv = &http.Server{
		Handler:           noStore(mux),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	// Bind synchronously so an occupied port or an unwritable socket path
	// fails setup, rather than logging into the void a moment later.
	ln, err := e.listen()
	if err != nil {
		return nil, err
	}
	s.ln = ln

	// Setup has to return a handler, not block, so serving runs in its own
	// goroutine. It is never stopped: plugin setup runs once for the life of
	// the process, and process exit is the only shutdown path there is.
	go func() {
		defer close(s.done)
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("leaseapi listener on %s stopped: %v", e.key(), err)
		}
	}()
	log.Infof("serving the lease API on %s (read-only, unauthenticated: %s)", e.key(), e.guard())
	return s, nil
}

// Lease state changes with every packet, so nothing served here may be
// cached, by a proxy an operator puts in front or by whatever asked.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Handler4 returns the response untouched; the plugin exists in the chain only to start the API listener.
func (s *server) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	return resp, false
}

// Handler6 returns the response untouched. See Handler4.
func (s *server) Handler6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	return resp, false
}
