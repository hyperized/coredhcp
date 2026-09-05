// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// This is a generated file, edits should be made in the corresponding source file
// And this file regenerated using
// `coredhcp-generator -t coredhcp-tui.go.template --from core-plugins.txt`

// The coredhcp-tui command runs the DHCP server with the built-in plugin set
// behind the terminal interface.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	flag "github.com/spf13/pflag"

	"github.com/coredhcp/coredhcp/cmd/coredhcp-tui/tui"
	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/events"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/server"

	pl_autoconfigure "github.com/coredhcp/coredhcp/plugins/autoconfigure"
	pl_dns "github.com/coredhcp/coredhcp/plugins/dns"
	pl_file "github.com/coredhcp/coredhcp/plugins/file"
	pl_ipv6only "github.com/coredhcp/coredhcp/plugins/ipv6only"
	pl_leasetime "github.com/coredhcp/coredhcp/plugins/leasetime"
	pl_macfilter "github.com/coredhcp/coredhcp/plugins/macfilter"
	pl_metrics "github.com/coredhcp/coredhcp/plugins/metrics"
	pl_mtu "github.com/coredhcp/coredhcp/plugins/mtu"
	pl_nbp "github.com/coredhcp/coredhcp/plugins/nbp"
	pl_netbox "github.com/coredhcp/coredhcp/plugins/netbox"
	pl_netmask "github.com/coredhcp/coredhcp/plugins/netmask"
	pl_ntp "github.com/coredhcp/coredhcp/plugins/ntp"
	pl_options "github.com/coredhcp/coredhcp/plugins/options"
	pl_prefix "github.com/coredhcp/coredhcp/plugins/prefix"
	pl_range "github.com/coredhcp/coredhcp/plugins/range"
	pl_redis "github.com/coredhcp/coredhcp/plugins/redis"
	pl_router "github.com/coredhcp/coredhcp/plugins/router"
	pl_searchdomains "github.com/coredhcp/coredhcp/plugins/searchdomains"
	pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"
	pl_staticroute "github.com/coredhcp/coredhcp/plugins/staticroute"
)

var (
	flagLogFile  = flag.StringP("logfile", "l", "", "Name of the log file to append to. Default: stdout/stderr only")
	flagLogLevel = flag.StringP("loglevel", "L", "info", fmt.Sprintf("Log level. One of %v", logger.Levels()))
	flagConfig   = flag.StringP("conf", "c", "", "Use this configuration file instead of the default location")
	flagPlugins  = flag.BoolP("plugins", "P", false, "list plugins")
)

var desiredPlugins = []*plugins.Plugin{
	&pl_autoconfigure.Plugin,
	&pl_dns.Plugin,
	&pl_file.Plugin,
	&pl_ipv6only.Plugin,
	&pl_leasetime.Plugin,
	&pl_macfilter.Plugin,
	&pl_metrics.Plugin,
	&pl_mtu.Plugin,
	&pl_nbp.Plugin,
	&pl_netbox.Plugin,
	&pl_netmask.Plugin,
	&pl_ntp.Plugin,
	&pl_options.Plugin,
	&pl_prefix.Plugin,
	&pl_range.Plugin,
	&pl_redis.Plugin,
	&pl_router.Plugin,
	&pl_searchdomains.Plugin,
	&pl_serverid.Plugin,
	&pl_staticroute.Plugin,
}

// terminal is what run needs from the interface: it observes the server, it
// takes the console log stream, and it owns the screen until the operator
// quits. tui.UI implements all of it. Tests replace newUI with something that
// needs no terminal.
type terminal interface {
	events.Observer

	LogWriter() io.Writer
	Run(ctx context.Context) error
	Stop()
}

// newUI builds the interface run draws on. It is a variable so tests can
// swap it for a fake.
var newUI = func(version string) terminal {
	return tui.New(tui.WithVersion(version))
}

// readBuildInfo is debug.ReadBuildInfo, as a variable so both branches of
// version() can be tested: a test binary has one build info and no way to
// change it.
var readBuildInfo = debug.ReadBuildInfo

func main() {
	flag.Parse()
	if err := run(os.Stdout); err != nil {
		logger.GetLogger("main").Fatal(err)
	}
}

// version reports what the interface shows in its header. Only a binary the
// go tool built from a module knows its version; a build from a checkout says
// "(devel)", the same string the go tool uses for it.
func version() string {
	info, ok := readBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// run starts the server and draws the interface until the operator quits or
// the server stops, whichever happens first. The plugin listing, the one
// thing this command prints outside the interface, goes to w. Split from main
// so it can be tested.
func run(w io.Writer) error {
	if *flagPlugins {
		for _, p := range desiredPlugins {
			if _, err := fmt.Fprintln(w, p.Name); err != nil {
				return err
			}
		}
		return nil
	}

	log := logger.GetLogger("main")
	if err := logger.SetLevel(*flagLogLevel); err != nil {
		return err
	}
	log.Infof("Setting log level to '%s'", *flagLogLevel)
	if *flagLogFile != "" {
		log.Infof("Logging to file %s", *flagLogFile)
		if err := logger.WithFile(*flagLogFile); err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
	}
	config, err := config.Load(*flagConfig)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	// register plugins
	for _, plugin := range desiredPlugins {
		if err := plugins.RegisterPlugin(plugin); err != nil {
			// The plugin is not named here because the only error
			// RegisterPlugin returns is for a nil entry, which has no name
			// to read.
			return fmt.Errorf("failed to register plugin: %w", err)
		}
	}

	ui := newUI(version())
	// The interface owns the terminal from here on, so the console stream
	// goes to its log pane instead of stderr. Put stderr back before
	// returning: anything logged while shutting down has to land somewhere
	// once the screen is gone.
	logger.WithConsole(ui.LogWriter())
	defer logger.WithConsole(os.Stderr)

	// start server
	srv, err := server.Start(config, server.WithObserver(ui))
	if err != nil {
		return err
	}

	// shut down cleanly on SIGINT/SIGTERM. Ctrl-C typed into the interface
	// never gets here: the screen is in raw mode and reads it as a key, so
	// this is for signals sent from outside, such as a service manager
	// stopping the unit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	// waitErr is written by the goroutine below and read after waitDone is
	// closed, which is what orders the two.
	var waitErr error
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		waitErr = srv.Wait()
		// The listeners are gone, so there is nothing left to draw. This is
		// what ends the interface after a signal, and also when a listener
		// dies on its own.
		ui.Stop()
	}()
	go func() {
		select {
		case s := <-sig:
			log.Infof("received %s, shutting down", s)
			srv.Close()
		case <-waitDone:
			// The server stopped without us asking. Leave, so this goroutine
			// does not outlive the run waiting for a signal.
		}
	}()

	runErr := ui.Run(context.Background())
	// Reached either because the operator quit, in which case the listeners
	// are still up and this is what stops them, or because the server is
	// already down, in which case closing again is a no-op.
	srv.Close()
	<-waitDone

	if runErr != nil {
		return runErr
	}
	// Wait reports nil for listeners that were closed on purpose, so this is
	// only non-nil when a listener failed. That has to reach the exit status:
	// nothing else is left to say the server stopped serving.
	return waitErr
}
