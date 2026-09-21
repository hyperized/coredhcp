// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Command helper stands in for two external systems in the docker compose
// end-to-end test of coredhcp: a mock of the two NetBox API endpoints the
// netbox plugin calls, and a webhook receiver for the leasehook plugin. It
// records every request it gets, in memory and on disk, so the test can
// assert that the plugins really called out and with what.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Server timeouts. The helper only ever serves small, local requests, so
// these are generous rather than tuned; their purpose is to stop a stalled
// client from holding a connection open forever.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 5 * time.Second
)

// config is the helper's configuration, read entirely from the environment
// so the compose file is the one place that sets it.
type config struct {
	addr              string
	resultsDir        string
	netboxToken       string
	leasehookSecret   string
	netboxMAC         string
	netboxMACNotFound string
	netboxAddr4       string
	netboxAddr6       string
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.resultsDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "creating results directory %s failed: %v; check HELPER_RESULTS points somewhere this process may write\n", cfg.resultsDir, err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	rec := newRecorder(cfg.resultsDir)
	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           newMux(cfg, rec),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	slog.Info("helper listening", "addr", cfg.addr, "fixture_mac", cfg.netboxMAC)
	run(srv)
}

// loadConfig reads the helper's configuration from the environment. A
// missing or empty required variable is reported as an error naming the
// variable and what to set it to; main turns that into the process's
// startup failure.
func loadConfig() (config, error) {
	cfg := config{
		addr:              getEnvDefault("HELPER_ADDR", ":8080"),
		resultsDir:        getEnvDefault("HELPER_RESULTS", "/results"),
		netboxMACNotFound: os.Getenv("NETBOX_MAC_NOTFOUND"),
	}

	required := []struct {
		dst  *string
		name string
		hint string
	}{
		{&cfg.netboxToken, "NETBOX_TOKEN", "the token the netbox plugin will present"},
		{&cfg.leasehookSecret, "LEASEHOOK_SECRET", "the HMAC key the leasehook plugin signs with"},
		{&cfg.netboxMAC, "NETBOX_MAC", "the one MAC address the mock knows about, lowercase colon form, e.g. 02:00:00:c0:de:31"},
		{&cfg.netboxAddr4, "NETBOX_ADDR4", "the IPv4 address documented on that MAC's interface, CIDR form, e.g. 172.31.246.20/24"},
		{&cfg.netboxAddr6, "NETBOX_ADDR6", "the IPv6 address, CIDR form, e.g. fd00:c0de:246::20/64"},
	}
	for _, req := range required {
		v, err := requireEnv(req.name, req.hint)
		if err != nil {
			return config{}, err
		}
		*req.dst = v
	}
	return cfg, nil
}

// getEnvDefault returns the environment variable name, or def when it is
// unset or empty.
func getEnvDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// requireEnv returns the environment variable name, or an error naming it
// and hint when it is unset or empty.
func requireEnv(name, hint string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is unset or empty; set it to %s", name, hint)
	}
	return v, nil
}

// newMux wires every route the helper serves.
func newMux(cfg config, rec *recorder) *http.ServeMux {
	mux := http.NewServeMux()

	nb := &netboxMock{
		token:       cfg.netboxToken,
		mac:         cfg.netboxMAC,
		macNotFound: cfg.netboxMACNotFound,
		addr4:       cfg.netboxAddr4,
		addr6:       cfg.netboxAddr6,
		rec:         rec,
	}
	wh := &webhookReceiver{secret: cfg.leasehookSecret, rec: rec}

	mux.HandleFunc("GET /api/dcim/mac-addresses/", nb.macAddresses)
	mux.HandleFunc("GET /api/ipam/ip-addresses/", nb.ipAddresses)
	mux.HandleFunc("POST /hook", wh.handle)
	mux.HandleFunc("GET /recorded/netbox", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rec.netboxRecords())
	})
	mux.HandleFunc("GET /recorded/webhook", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rec.webhookRecords())
	})
	mux.HandleFunc("GET /healthz", healthz)

	return mux
}

// healthz answers the container healthcheck.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// writeJSON writes body as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("encoding a JSON response failed", "error", err)
	}
}

// run starts srv and blocks until it exits, either because it failed on its
// own or because SIGINT or SIGTERM asked for a graceful shutdown.
func run(srv *http.Server) {
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil {
			slog.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-sig:
		slog.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown did not finish in time", "error", err)
		}
	}
}
