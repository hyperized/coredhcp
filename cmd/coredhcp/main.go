// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// This is a generated file, edits should be made in the corresponding source file
// And this file regenerated using `coredhcp-generator --from core-plugins.txt`

// The coredhcp command runs the DHCP server with the built-in plugin set.
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"

	"github.com/coredhcp/coredhcp/config"
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
	pl_netmask "github.com/coredhcp/coredhcp/plugins/netmask"
	pl_ntp "github.com/coredhcp/coredhcp/plugins/ntp"
	pl_options "github.com/coredhcp/coredhcp/plugins/options"
	pl_prefix "github.com/coredhcp/coredhcp/plugins/prefix"
	pl_range "github.com/coredhcp/coredhcp/plugins/range"
	pl_router "github.com/coredhcp/coredhcp/plugins/router"
	pl_searchdomains "github.com/coredhcp/coredhcp/plugins/searchdomains"
	pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"
	pl_sleep "github.com/coredhcp/coredhcp/plugins/sleep"
	pl_staticroute "github.com/coredhcp/coredhcp/plugins/staticroute"
)

var (
	flagLogFile     = flag.StringP("logfile", "l", "", "Name of the log file to append to. Default: stdout/stderr only")
	flagLogNoStdout = flag.BoolP("nostdout", "N", false, "Disable logging to stdout/stderr")
	flagLogLevel    = flag.StringP("loglevel", "L", "info", fmt.Sprintf("Log level. One of %v", logger.Levels()))
	flagConfig      = flag.StringP("conf", "c", "", "Use this configuration file instead of the default location")
	flagPlugins     = flag.BoolP("plugins", "P", false, "list plugins")
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
	&pl_netmask.Plugin,
	&pl_ntp.Plugin,
	&pl_options.Plugin,
	&pl_prefix.Plugin,
	&pl_range.Plugin,
	&pl_router.Plugin,
	&pl_searchdomains.Plugin,
	&pl_serverid.Plugin,
	&pl_sleep.Plugin,
	&pl_staticroute.Plugin,
}

func main() {
	flag.Parse()
	if err := run(os.Stdout); err != nil {
		logger.GetLogger("main").Fatal(err)
	}
}

// run executes the server with the parsed flag values, writing informational
// output to w. Split from main so it can be tested.
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
	if *flagLogNoStdout {
		log.Infof("Disabling logging to stdout/stderr")
		logger.WithNoStdOutErr()
	}
	config, err := config.Load(*flagConfig)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	// register plugins
	for _, plugin := range desiredPlugins {
		if err := plugins.RegisterPlugin(plugin); err != nil {
			return fmt.Errorf("failed to register plugin '%s': %w", plugin.Name, err)
		}
	}

	// start server
	srv, err := server.Start(config)
	if err != nil {
		return err
	}

	// shut down cleanly on SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		s := <-sig
		log.Infof("received %s, shutting down", s)
		srv.Close()
	}()

	if err := srv.Wait(); err != nil {
		log.Error(err)
	}
	return nil
}
