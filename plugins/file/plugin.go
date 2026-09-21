// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
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
	keyArg         = "key:"
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

// options is one instance's parsed configuration.
type options struct {
	filename    string
	autorefresh bool
	mode        keyMode
}

// parseArgs reads a config line: the lease file name, followed by any of the
// optional arguments in any order.
func parseArgs(v6 bool, args []string) (options, error) {
	var opts options
	if len(args) < 1 {
		return opts, errors.New("no lease file given; pass the file name as the first argument, for example file: \"leases4.txt\"")
	}
	opts.filename = args[0]
	if opts.filename == "" {
		return opts, errors.New("the lease file name is empty; pass a path, for example file: \"leases4.txt\"")
	}
	for _, arg := range args[1:] {
		if err := opts.apply(arg); err != nil {
			return opts, err
		}
	}
	return opts, opts.mode.checkFamily(v6)
}

// apply reads one optional argument.
func (o *options) apply(arg string) error {
	if arg == autoRefreshArg {
		o.autorefresh = true
		return nil
	}
	raw, ok := strings.CutPrefix(arg, keyArg)
	if !ok {
		return fmt.Errorf("argument %q is not recognised; use %s or %s<mac|duid|client-id>", arg, autoRefreshArg, keyArg)
	}
	mode, err := parseKeyMode(raw)
	if err != nil {
		return err
	}
	o.mode = mode
	return nil
}

// pluginState holds the identifier -> IP address mapping backing a single
// instance of the file plugin, plus the lock protecting it. setupFile creates
// one instance per call, so a deployment using the plugin on both server4 and
// server6 keeps their lease sets independent.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]netip.Addr

	// name identifies this instance to a lease reader and family says which
	// protocol its reservations are for. Both are set during setup and
	// read-only afterwards; see leases.go.
	name   string
	family uint8
	// mode is what recs is keyed on. It is set once, before the handlers or
	// the autorefresh goroutine exist, and read without the lock after that.
	mode keyMode
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
		log.Errorf("BUG: cannot read the client message inside the relayed request, dropping it: %v; the client will retry, report this with the server log", err)
		return nil, true
	}

	if skipsLookup6(m.MessageType) {
		return resp, false
	}

	if m.Options.OneIANA() == nil {
		log.Debug("No address requested")
		return resp, false
	}

	key, ok := s.mode.key6(req, m)
	if !ok {
		return resp, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ipaddr, found := s.recs[key]
	if !found {
		log.Infof("%s %s is unknown", s.mode.label(), key)
		return resp, false
	}
	log.Infof("%s %s given IP address %s", s.mode.label(), key, ipaddr)

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

// skipsLookup6 reports whether mtype is a DHCPv6 message that gets no IA_NA
// from this plugin. A Reply to a Release or Decline must not hand the address
// back to the client, whatever reservation the client has.
func skipsLookup6(mtype dhcpv6.MessageType) bool {
	switch mtype {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// Handler4 handles DHCPv4 packets for the file plugin
func (s *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if skipsLookup4(req.MessageType()) {
		return resp, false
	}

	key, ok := s.mode.key4(req)
	if !ok {
		return resp, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ipaddr, found := s.recs[key]
	if !found {
		log.Infof("%s %s is unknown", s.mode.label(), key)
		return resp, false
	}
	resp.YourIPAddr = ipaddr.AsSlice()
	log.Infof("%s %s given IP address %s", s.mode.label(), key, ipaddr)
	return resp, true
}

// skipsLookup4 reports whether mtype is a DHCPv4 message the plugin passes on
// untouched. An INFORM asks for options only, and a static reservation has
// nothing to free when a client gives an address up or rejects it.
func skipsLookup4(mtype dhcpv4.MessageType) bool {
	switch mtype {
	case dhcpv4.MessageTypeInform, dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
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
	opts, err := parseArgs(v6, args)
	if err != nil {
		return nil, nil, err
	}

	s := &pluginState{name: "file " + opts.filename, family: familyOf(v6), mode: opts.mode}

	// load initial database from lease file
	if err := s.loadFromFile(v6, opts.filename); err != nil {
		return nil, nil, err
	}

	// when the 'autorefresh' argument was passed, watch the lease file for
	// changes and reload the lease mapping on any event
	if opts.autorefresh {
		if err := s.watchFile(v6, opts.filename); err != nil {
			return nil, nil, err
		}
	}

	// Registered last, once everything that could fail has succeeded: a
	// reader must never find a half-built instance in the registry.
	leases.Register(s)
	log.Infof("loaded %d leases from %s", s.numRecords(), opts.filename)
	return s.Handler6, s.Handler4, nil
}

// watchFile starts the autorefresh watcher. A reload that fails keeps the
// leases that were already loaded: a lease file caught half written is a poor
// reason to stop answering the clients that are already in it.
//
// The directory is watched rather than the file, since a watch on the file
// follows the inode a rename unlinked and would miss every update after the
// first.
func (s *pluginState) watchFile(v6 bool, filename string) error {
	watcher, err := fsnotifyNewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create a file watcher for autorefresh: %w; check the inotify limits, or drop the %s argument", err, autoRefreshArg)
	}

	dir := filepath.Dir(filename)
	if err := watcherAdd(watcher, dir); err != nil {
		return fmt.Errorf("cannot watch directory %s for changes: %w; check that it exists and the server's user may read it, or drop the %s argument", dir, err, autoRefreshArg)
	}

	go s.watchLoop(v6, filename, watcher)
	return nil
}

// watchLoop is split out of watchFile so a test can drive it with a watcher
// it controls instead of real filesystem events.
func (s *pluginState) watchLoop(v6 bool, filename string, watcher *fsnotify.Watcher) {
	base := filepath.Base(filename)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(event.Name) != base {
				continue
			}
			s.refresh(v6, filename)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			// An error on a live watch means events were dropped, a full
			// inotify queue being the usual cause, so the mapping may already
			// be behind the file. The channel has to be drained either way:
			// fsnotify blocks on it until someone reads.
			log.Warningf("the watch on %s reported an error: %s; events may have been dropped, the file is being reread now", filename, err)
			s.refresh(v6, filename)
		}
	}
}

func (s *pluginState) refresh(v6 bool, filename string) {
	if err := s.loadFromFile(v6, filename); err != nil {
		log.Warningf("cannot reread %s: %s; the leases already loaded stay in force, fix the file and save it again", filename, err)
		return
	}
	log.Infof("updated to %d leases from %s", s.numRecords(), filename)
}

func (s *pluginState) loadFromFile(v6 bool, filename string) error {
	records, err := loadRecords(filename, v6, s.mode)
	if err != nil {
		return fmt.Errorf("cannot load the DHCPv%d leases: %w", protoVersion(v6), err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.recs = records

	return nil
}
