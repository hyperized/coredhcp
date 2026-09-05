// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package file enables static mapping of MAC <--> IP addresses.
// The mapping is stored in a text file, where each mapping is described by one line containing
// two fields separated by whitespace: MAC address and IP address. For example:
//
//	$ cat leases_v4.txt
//	# IPv4 fixed addresses
//	00:11:22:33:44:55 10.0.0.1
//	a1:b2:c3:d4:e5:f6 10.0.10.10  # lowercase is permitted
//
//	$ cat leases_v6.txt
//	# IPv6 fixed addresses
//	00:11:22:33:44:55 2001:db8::10:1
//	A1:B2:C3:D4:E5:F6 2001:db8::10:2
//
// Any text following '#' is a comment that is ignored.
//
// MAC addresses can be upper or lower case. IPv6 addresses should use lowercase, as per RFC-5952.
//
// Each MAC or IP address should normally be unique within the file. Warnings will be logged for
// any duplicates.
//
// To specify the plugin configuration in the server6/server4 sections of the config file, just
// pass the leases file name as plugin argument, e.g.:
//
//	$ cat config.yml
//
//	server6:
//	   ...
//	   plugins:
//	     - file: "file_leases.txt" [autorefresh]
//	   ...
//
// If the file path is not absolute, it is relative to the cwd where coredhcp is run.
//
// The optional keyword 'autorefresh' can be used as shown, or it can be omitted. When
// present, the plugin will try to refresh the lease mapping during runtime whenever
// the lease file is updated.
//
// For DHCPv4 `server4`, note that the file plugin must come after any general plugins
// needed, e.g. dns or router. The order is unimportant for DHCPv6, but will affect the
// order of options in the DHCPv6 response.
//
// The plugin does not act on RELEASE or DECLINE messages. Its mappings are static, so
// there is no lease to reclaim when a client gives one up or rejects one.
package file

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/leases"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

const (
	autoRefreshArg = "autorefresh"
)

var log = logger.GetLogger("plugins/file")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "file",
	Setup6: setup6,
	Setup4: setup4,
}

// fsnotifyNewWatcher and watcherAdd are indirections over the two fsnotify
// calls setupFile makes to wire up autorefresh. Production code always uses
// the real implementations assigned here; tests substitute them to simulate
// the watcher failing to initialize or attach, which real filesystem
// operations can't trigger deterministically.
var (
	fsnotifyNewWatcher = fsnotify.NewWatcher
	watcherAdd         = (*fsnotify.Watcher).Add
)

// pluginState holds the MAC -> IP address mapping backing a single instance
// of the file plugin, plus the lock protecting it. setupFile creates one
// instance per call, so a deployment using the plugin on both server4 and
// server6 keeps their lease sets independent.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]netip.Addr

	// name identifies this instance to a lease reader and family says which
	// protocol its reservations are for. Both are set during setup and
	// read-only afterwards; see leases.go.
	name   string
	family uint8
}

// numRecords returns the number of currently loaded records.
func (s *pluginState) numRecords() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recs)
}

// Handler6 handles DHCPv6 packets for the file plugin
func (s *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate: %v", err)
		return nil, true
	}

	// A Reply to a Release or Decline must not hand the address back to the
	// client, so skip adding an IA_NA regardless of what the client asked for.
	if m.MessageType == dhcpv6.MessageTypeRelease || m.MessageType == dhcpv6.MessageTypeDecline {
		return resp, false
	}

	if m.Options.OneIANA() == nil {
		log.Debug("No address requested")
		return resp, false
	}

	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		log.Infof("Could not find client MAC for %s, passing", req)
		return resp, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ipaddr, ok := s.recs[mac.String()]
	if !ok {
		log.Infof("MAC address %s is unknown", mac)
		return resp, false
	}
	log.Infof("MAC address %s given IP address %s", mac, ipaddr)

	resp.AddOption(&dhcpv6.OptIANA{
		IaId: m.Options.OneIANA().IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          ipaddr.AsSlice(),
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     3600 * time.Second,
			},
		}},
	})
	return resp, false
}

// Handler4 handles DHCPv4 packets for the file plugin
func (s *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	// INFORM asks for options only, and a static reservation has nothing to
	// free when a client gives an address up or rejects it. All three pass
	// through untouched for the plugins that come after this one.
	if mt := req.MessageType(); mt == dhcpv4.MessageTypeInform ||
		mt == dhcpv4.MessageTypeRelease || mt == dhcpv4.MessageTypeDecline {
		return resp, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipaddr, ok := s.recs[req.ClientHWAddr.String()]
	if !ok {
		log.Infof("MAC address %s is unknown", req.ClientHWAddr)
		return resp, false
	}
	resp.YourIPAddr = ipaddr.AsSlice()
	log.Infof("MAC address %s given IP address %s", req.ClientHWAddr, ipaddr)
	return resp, true
}

func setup6(args ...string) (handler.Handler6, error) {
	h6, _, err := setupFile(true, args...)
	return h6, err
}

func setup4(args ...string) (handler.Handler4, error) {
	_, h4, err := setupFile(false, args...)
	return h4, err
}

func setupFile(v6 bool, args ...string) (handler.Handler6, handler.Handler4, error) {
	var err error
	if len(args) < 1 {
		return nil, nil, errors.New("need a file name")
	}
	filename := args[0]
	if filename == "" {
		return nil, nil, errors.New("got empty file name")
	}

	s := &pluginState{name: "file " + filename, family: familyOf(v6)}

	// load initial database from lease file
	if err = s.loadFromFile(v6, filename); err != nil {
		return nil, nil, err
	}

	// when the 'autorefresh' argument was passed, watch the lease file for
	// changes and reload the lease mapping on any event
	if len(args) > 1 && args[1] == autoRefreshArg {
		// creates a new file watcher
		watcher, err := fsnotifyNewWatcher()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create watcher: %w", err)
		}

		// have file watcher watch over lease file
		if err = watcherAdd(watcher, filename); err != nil {
			return nil, nil, fmt.Errorf("failed to watch %s: %w", filename, err)
		}

		// very simple watcher on the lease file to trigger a refresh on any event
		// on the file
		go func() {
			for range watcher.Events {
				err := s.loadFromFile(v6, filename)
				if err != nil {
					log.Warningf("failed to refresh from %s: %s", filename, err)

					continue
				}

				log.Infof("updated to %d leases from %s", s.numRecords(), filename)
			}
		}()
	}

	// Registered last, once everything that could fail has succeeded: a
	// reader must never find a half-built instance in the registry.
	leases.Register(s)
	log.Infof("loaded %d leases from %s", s.numRecords(), filename)
	return s.Handler6, s.Handler4, nil
}

func (s *pluginState) loadFromFile(v6 bool, filename string) error {
	var err error
	var records map[string]netip.Addr
	var protver int
	if v6 {
		protver = 6
		records, err = LoadDHCPv6Records(filename)
	} else {
		protver = 4
		records, err = LoadDHCPv4Records(filename)
	}
	if err != nil {
		return fmt.Errorf("failed to load DHCPv%d records: %w", protver, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.recs = records

	return nil
}
