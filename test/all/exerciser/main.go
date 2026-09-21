// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Command exerciser drives one scenario per core plugin against the coredhcp
// server of the test/all compose stack and reports which of them behaved as
// its package documentation promises.
//
// It is a DHCP client, a DHCP relay and a reader of the server's own side
// channels at once. The client and the relay live on two different bridges,
// which is what lets a single container send a request the relay plugin will
// answer and one it will refuse without any extra host in the stack.
//
// Expectations come from the configuration the server was started with,
// parsed out of the mounted config.yaml, rather than from a second copy of
// the same addresses here. A configuration change the clients do not see
// then fails a scenario instead of quietly going unchecked.
//
// The exit code is the result of the run and, through
// `up --exit-code-from exerciser`, of the whole stack: 0 when every scenario
// passed, 1 when any of them did not, 2 when the stack could not be reached
// well enough to start.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coredhcp/coredhcp/test/all/internal/serverconf"
)

const (
	// exitSetup is for a stack that could not be reached at all, as opposed
	// to a plugin that misbehaved. The two look nothing alike in a CI log
	// and should not share an exit code.
	exitSetup = 2

	// httpBudget bounds a call to the lease API, the metrics endpoint or the
	// mock. All three are local and answer from memory.
	httpBudget = 10 * time.Second
)

// world is everything a scenario can reach: the sockets, the server's own
// configuration, the side channels, and the handful of facts one scenario
// leaves behind for the next.
type world struct {
	s   *settings
	cfg *serverconf.Config

	v4 *dhcp4
	v6 *dhcp6

	leaseAPI *http.Client
	metrics  *http.Client
	helper   *http.Client

	// notes are attached to whichever scenario is running, and printed only
	// when it fails. A passing run stays readable.
	notes []string

	// Facts carried between scenarios. A lease has to exist before the lease
	// API can be asked to list it, and the address a client released has to
	// be known before anyone can check it came back.
	pool     leaseFact
	released leaseFact
	declined leaseFact
	v6Lease  leaseFact
	v6PD     leaseFact

	// The clients whose DNS records the ddns scenarios read back: one with a
	// name of its own, the first of two that asked for the same name, and
	// one that asked for a name the plugin protects.
	ddnsOwn       leaseFact
	ddnsShared    leaseFact
	ddnsProtected leaseFact
	ddnsOwn6      leaseFact
}

// leaseFact is one address a scenario handed out, kept for the scenarios
// that check what happened to it afterwards.
type leaseFact struct {
	mac      net.HardwareAddr
	addr     netip.Addr
	hostname string
}

func (w *world) note(format string, args ...any) {
	w.notes = append(w.notes, fmt.Sprintf(format, args...))
}

func main() {
	os.Exit(run())
}

func run() int {
	s, err := loadSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "exerciser: %v\n", err)
		return exitSetup
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	w, err := newWorld(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exerciser: %v\n", err)
		return exitSetup
	}
	defer w.close()

	fmt.Printf("exerciser: client side %s on %s, relay side %s\n", s.selfLAN4, w.v4.iface.Name, s.selfRLY4)
	fmt.Printf("exerciser: chain server4 %v\n", w.cfg.Server4.Names())
	fmt.Printf("exerciser: chain server6 %v\n", w.cfg.Server6.Names())

	scenarios := allScenarios()
	results := runAll(ctx, w, scenarios)
	return writeReport(os.Stdout, results)
}

// allScenarios is the whole table, in the order it has to run: the DHCPv4
// exchanges that leave leases behind, then the relayed ones, then DHCPv6,
// then the side effects those leases should have had, and last the two that
// drain the pool on purpose.
func allScenarios() []scenario {
	out := make([]scenario, 0, 48)
	out = append(out, scenarios4()...)
	out = append(out, scenarios4Relay()...)
	out = append(out, scenarios6()...)
	out = append(out, scenariosSideEffects()...)
	out = append(out, scenariosLast()...)
	return out
}

func newWorld(s *settings) (*world, error) {
	cfg, err := serverconf.Load(s.configPath)
	if err != nil {
		return nil, err
	}
	if len(cfg.Server4) == 0 || len(cfg.Server6) == 0 {
		return nil, fmt.Errorf("%s configures %d server4 and %d server6 plugins; the stack expects both families",
			s.configPath, len(cfg.Server4), len(cfg.Server6))
	}

	v4, err := newDHCP4(s.selfLAN4)
	if err != nil {
		return nil, err
	}
	v6, err := newDHCP6(s.selfLAN6, s.serverLAN6, s.serverRLY6)
	if err != nil {
		_ = v4.Close()
		return nil, err
	}

	return &world{
		s:        s,
		cfg:      cfg,
		v4:       v4,
		v6:       v6,
		leaseAPI: unixClient(s.leaseAPISocket),
		metrics:  unixClient(s.metricsSocket),
		helper:   &http.Client{Timeout: httpBudget},
	}, nil
}

func (w *world) close() {
	_ = w.v4.Close()
	_ = w.v6.Close()
}

// unixClient talks HTTP over a unix socket. Both the lease API and the
// metrics endpoint bind one rather than a loopback port, which is what the
// endpoint package calls the whole of their access control: a socket in a
// volume only the stack mounts.
func unixClient(path string) *http.Client {
	return &http.Client{
		Timeout: httpBudget,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}
