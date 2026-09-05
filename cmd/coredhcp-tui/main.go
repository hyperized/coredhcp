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
	pl_bootfile "github.com/coredhcp/coredhcp/plugins/bootfile"
	pl_ddns "github.com/coredhcp/coredhcp/plugins/ddns"
	pl_dns "github.com/coredhcp/coredhcp/plugins/dns"
	pl_file "github.com/coredhcp/coredhcp/plugins/file"
	pl_ipv6only "github.com/coredhcp/coredhcp/plugins/ipv6only"
	pl_leaseapi "github.com/coredhcp/coredhcp/plugins/leaseapi"
	pl_leasehook "github.com/coredhcp/coredhcp/plugins/leasehook"
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
	pl_range6 "github.com/coredhcp/coredhcp/plugins/range6"
	pl_ratelimit "github.com/coredhcp/coredhcp/plugins/ratelimit"
	pl_redis "github.com/coredhcp/coredhcp/plugins/redis"
	pl_relay "github.com/coredhcp/coredhcp/plugins/relay"
	pl_relayinfo "github.com/coredhcp/coredhcp/plugins/relayinfo"
	pl_router "github.com/coredhcp/coredhcp/plugins/router"
	pl_searchdomains "github.com/coredhcp/coredhcp/plugins/searchdomains"
	pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"
	pl_staticroute "github.com/coredhcp/coredhcp/plugins/staticroute"
	pl_subnet "github.com/coredhcp/coredhcp/plugins/subnet"
)

var (
	flagLogFile  = flag.StringP("logfile", "l", "", "Name of the log file to append to. Default: stdout/stderr only")
	flagLogLevel = flag.StringP("loglevel", "L", "info", fmt.Sprintf("Log level. One of %v", logger.Levels()))
	flagConfig   = flag.StringP("conf", "c", "", "Use this configuration file instead of the default location")
	flagPlugins  = flag.BoolP("plugins", "P", false, "list plugins")
)

var desiredPlugins = []*plugins.Plugin{
	&pl_autoconfigure.Plugin,
	&pl_bootfile.Plugin,
	&pl_ddns.Plugin,
	&pl_dns.Plugin,
	&pl_file.Plugin,
	&pl_ipv6only.Plugin,
	&pl_leaseapi.Plugin,
	&pl_leasehook.Plugin,
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
	&pl_range6.Plugin,
	&pl_ratelimit.Plugin,
	&pl_redis.Plugin,
	&pl_relay.Plugin,
	&pl_relayinfo.Plugin,
	&pl_router.Plugin,
	&pl_searchdomains.Plugin,
	&pl_serverid.Plugin,
	&pl_staticroute.Plugin,
	&pl_subnet.Plugin,
}

// terminal is what run needs of the interface, kept an interface so a test
// can drive run without a terminal.
type terminal interface {
	events.Observer

	LogWriter() io.Writer
	Run(ctx context.Context) error
	Stop()
}

// A variable so tests can swap in a fake.
var newUI = func(version string) terminal {
	return tui.New(tui.WithVersion(version))
}

// A variable: a test binary has one build info and no way to change it.
var readBuildInfo = debug.ReadBuildInfo

func main() {
	flag.Parse()
	if err := run(os.Stdout); err != nil {
		logger.GetLogger("main").Fatal(err)
	}
}

// A build from a checkout has no module version and says "(devel)", the same
// string the go tool uses for it.
func version() string {
	info, ok := readBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// run draws the interface until the operator quits or the server stops.
// Split from main so it can be tested; w takes the plugin listing.
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
	for _, plugin := range desiredPlugins {
		if err := plugins.RegisterPlugin(plugin); err != nil {
			// Unnamed: RegisterPlugin only errors on a nil entry.
			return fmt.Errorf("failed to register plugin: %w", err)
		}
	}

	ui := newUI(version())
	// The interface owns the terminal from here on. Put stderr back before
	// returning, so shutdown logging still lands somewhere.
	logger.WithConsole(ui.LogWriter())
	defer logger.WithConsole(os.Stderr)

	srv, err := server.Start(config, server.WithObserver(ui))
	if err != nil {
		return err
	}

	// Ctrl-C never gets here: the screen is in raw mode and reads it as a key,
	// so this is only for signals sent from outside.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	// waitErr is ordered by waitDone: written before the close, read after.
	var waitErr error
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		waitErr = srv.Wait()
		// Listeners gone, nothing left to draw.
		ui.Stop()
	}()
	go func() {
		select {
		case s := <-sig:
			log.Infof("received %s, shutting down", s)
			srv.Close()
		case <-waitDone:
			// Server stopped on its own; leave rather than outlive the run.
		}
	}()

	runErr := ui.Run(context.Background())
	// Either the operator quit and this stops the listeners, or the server is
	// already down and closing again is a no-op.
	srv.Close()
	<-waitDone

	if runErr != nil {
		return runErr
	}
	// Wait is nil for listeners closed on purpose, so an error here has to
	// reach the exit status; nothing else says the server stopped serving.
	return waitErr
}
