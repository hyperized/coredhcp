// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leaseapi serves the leases the server currently holds over a
// read-only HTTP API, on a unix socket or on loopback.
//
// Nothing in coredhcp could answer "who holds what right now"
// (coredhcp/coredhcp#111, the most-asked-for thing in that tracker), which
// also makes a remote terminal UI impossible: every lease lives in a plugin's
// own map behind that plugin's own lock. The lease-holding plugins now
// register themselves with the leases package during setup, and this plugin
// serves what the registry reports.
//
//	server4:
//	  plugins:
//	    - leaseapi: unix:/run/coredhcp/api.sock mode:0660
//	    - leaseapi: tcp:127.0.0.1:9755
//
// # There is no authentication
//
// The socket's permissions are the authentication, which is why the default
// mode is 0600 and why a tcp address has to be a loopback one. An operator who
// wants this reachable from another host puts a reverse proxy in front of it
// and authenticates there, or forwards the socket over ssh. Serving it on a
// routable address would publish every client MAC, DUID, hostname and address
// on the network to anyone who can reach the port.
//
// The API is read-only. There is no endpoint that frees a lease, edits a
// reservation or changes the configuration, and there is no plan for one:
// writes would need an authorisation model this has no way to provide, and a
// forged DHCPRELEASE is already the cheapest way to attack a pool.
//
// # Where it goes in the chain
//
// Anywhere. Both handlers return the response untouched and never end the
// chain; the plugin exists in the chain only because setup is what starts the
// listener. When server4 and server6 both configure the same address they
// share one listener, and the answers cover both families either way, since
// the registry is global.
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
//
// The plugin takes the address to listen on, and for a unix socket an optional
// mode:
//
//	plugins:
//	  - leaseapi: unix:/run/coredhcp/api.sock [mode:0660]
//	  - leaseapi: tcp:127.0.0.1:9755
//
// A second server section naming the same address shares the listener. Naming
// a different one is a setup error: there is a single registry behind these
// endpoints, so a second listener would only serve the same answers twice.
var Plugin = plugins.Plugin{
	Name:   "leaseapi",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	// Timeouts for the API. A request is a read of a few maps and a JSON
	// encode, so these only exist to keep a stuck or hostile client from
	// holding a connection open indefinitely. The write timeout is the
	// loosest of them because a large lease set streams out over it.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second

	// maxHeaderBytes caps request headers at 1 MiB, the net/http default
	// stated rather than inherited: this endpoint answers a handful of fixed
	// paths and has no use for large headers.
	maxHeaderBytes = 1 << 20
)

// registry maps a configured listen address to the server behind it.
//
// This is deliberately package-level shared state, for the same reason the
// metrics plugin keeps one: setup functions receive nothing but their
// arguments, and server4 and server6 have no other way to end up sharing a
// listener. The key is the network and address, so a second setup on the same
// address is a no-op returning the running server, mode: and all.
//
// mu guards the map only. Serving a request never takes it.
var registry = struct {
	mu      sync.Mutex
	servers map[string]*server
}{servers: make(map[string]*server)}

// server is one HTTP listener serving the API.
//
// It holds no lease state of its own: every request reads the leases registry
// afresh, so an answer is as current as the moment it was asked for.
type server struct {
	srv *http.Server
	ln  net.Listener
	// done is closed when the serve goroutine returns. Nothing in production
	// waits on it; tests do, so they can tear a listener down without
	// sleeping.
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

// setup validates the plugin arguments and returns the server to answer from,
// starting the listener if this is the first setup for that address.
func setup(args []string) (*server, error) {
	e, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	return obtain(e)
}

// obtain returns the server for e, starting a listener the first time the
// address is seen.
//
// One address per process is the whole contract: a second server section
// either names the same address, and shares the listener, or the configuration
// asks for two endpoints over one registry, which is a mistake worth failing
// on at startup rather than resolving silently.
func obtain(e endpoint) (*server, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	key := e.key()
	if s, ok := registry.servers[key]; ok {
		return s, nil
	}
	for running := range registry.servers {
		// The map holds at most one entry, so this loop reads the address
		// already bound and returns; see the doc comment above.
		return nil, fmt.Errorf("leaseapi: already listening on %s, refusing to also listen on %s", running, key)
	}
	s, err := newServer(e)
	if err != nil {
		return nil, err
	}
	registry.servers[key] = s
	return s, nil
}

// newServer binds e and starts serving the API on it.
func newServer(e endpoint) (*server, error) {
	s := &server{done: make(chan struct{})}

	mux := http.NewServeMux()
	// The method and path filtering is the ServeMux pattern's job (Go 1.22+):
	// any other path gets a 404, a known path with another method a 405. Both
	// come back as the mux's own plain-text body; everything this package
	// writes itself is JSON.
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
	// fails the setup and the server refuses to start, rather than logging
	// into the void a second later.
	ln, err := e.listen()
	if err != nil {
		return nil, err
	}
	s.ln = ln

	// Serving is asynchronous: setup has to return a handler, not block.
	//
	// The server is never stopped. Plugin setup in this fork runs once at
	// startup and the handlers it returns live for the lifetime of the
	// process, so there is no teardown hook to hang a Shutdown call on.
	// Process exit is the only shutdown path there is, and it takes the
	// socket file with it.
	go func() {
		defer close(s.done)
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("leaseapi listener on %s stopped: %v", e.key(), err)
		}
	}()
	log.Infof("serving the lease API on %s (read-only, unauthenticated: %s)", e.key(), e.guard())
	return s, nil
}

// noStore stamps Cache-Control on every response, the mux's own 404 and 405
// included. Lease state changes with every packet, so nothing served here may
// be cached, by a proxy an operator puts in front of it or by whatever asked.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Handler4 returns the response untouched.
//
// This plugin answers no DHCP traffic at all: it is in the chain only because
// setup is what starts the API listener. It never ends the chain, so it can
// sit anywhere in it.
func (s *server) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	return resp, false
}

// Handler6 returns the response untouched. See Handler4.
func (s *server) Handler6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	return resp, false
}
