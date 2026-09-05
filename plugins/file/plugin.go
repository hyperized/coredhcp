// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package file enables static mapping of client identifiers to IP addresses.
// The mapping is stored in a text file, where each mapping is described by one line containing
// two fields separated by whitespace: the client identifier and the IP address. For example:
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
// Each identifier or IP address should normally be unique within the file. Warnings will be
// logged for any duplicates.
//
// To specify the plugin configuration in the server6/server4 sections of the config file, just
// pass the leases file name as plugin argument, e.g.:
//
//	$ cat config.yml
//
//	server6:
//	   ...
//	   plugins:
//	     - file: "file_leases.txt" [autorefresh] [key:mac|duid|client-id]
//	   ...
//
// If the file path is not absolute, it is relative to the cwd where coredhcp is run.
//
// The two optional arguments may be given in either order. An argument that is neither of them
// fails setup by name, so a typo shows up at startup instead of being ignored.
//
// The keyword 'autorefresh' can be used as shown, or it can be omitted. When present, the plugin
// will try to refresh the lease mapping during runtime whenever the lease file is updated.
//
// # Lookup key
//
// The 'key:' argument says which identifier the first field of a lease line holds. It defaults
// to 'mac', the historical behaviour and the only mode both families accept.
//
// 'key:duid' is for server6 and fails setup under server4. A MAC address is a poor key there: a
// client identifying with a DUID-EN or a DUID-UUID carries no link-layer address in its DUID,
// and behind a relay that sends no client link-layer address option there is nothing to extract
// either. The first field is then the DUID as it goes on the wire, two-octet type code included,
// written in hexadecimal in either case, with an optional 0x prefix and optional colons between
// the bytes. These three lines name the same client:
//
//	0x00030001aabbccddeeff 2001:db8::10:1
//	00:03:00:01:aa:bb:cc:dd:ee:ff 2001:db8::10:1
//	00030001AABBCCDDEEFF 2001:db8::10:1
//
// A DUID is at most 130 octets, since RFC 8415 section 11.1 caps it at 128 and the type code is
// two more. A longer one is a setup error in the file, and a request carrying one is passed to
// the next plugin rather than looked up.
//
// 'key:client-id' is for server4 and fails setup under server6. It matches the raw bytes of
// option 61. RFC 2132 section 9.14 puts a type octet first: type 1 is a hardware address, so a
// client whose identifier is its MAC appears as 01 followed by the six address bytes, and an RFC
// 4361 client puts a DUID behind type 255. Everything else is opaque, and an identifier that
// reads as text can be written with a 'text:' prefix instead of as hexadecimal:
//
//	0x01aabbccddeeff 10.0.0.1
//	01:aa:bb:cc:dd:ee:ff 10.0.0.1
//	text:printer-2nd-floor 10.0.0.2
//
// A 'text:' value cannot contain whitespace, because lines are split on it. A client that sends
// no option 61 at all is passed to the next plugin.
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
		return opts, errors.New("need a file name")
	}
	opts.filename = args[0]
	if opts.filename == "" {
		return opts, errors.New("got empty file name")
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
		return fmt.Errorf("unknown argument %q, want %s or %s<mac|duid|client-id>", arg, autoRefreshArg, keyArg)
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
		log.Errorf("BUG: could not decapsulate: %v", err)
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
func (s *pluginState) watchFile(v6 bool, filename string) error {
	watcher, err := fsnotifyNewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	if err := watcherAdd(watcher, filename); err != nil {
		return fmt.Errorf("failed to watch %s: %w", filename, err)
	}

	// very simple watcher on the lease file to trigger a refresh on any event
	// on the file
	go func() {
		for range watcher.Events {
			if err := s.loadFromFile(v6, filename); err != nil {
				log.Warningf("failed to refresh from %s: %s", filename, err)

				continue
			}

			log.Infof("updated to %d leases from %s", s.numRecords(), filename)
		}
	}()
	return nil
}

func (s *pluginState) loadFromFile(v6 bool, filename string) error {
	records, err := loadRecords(filename, v6, s.mode)
	if err != nil {
		return fmt.Errorf("failed to load DHCPv%d records: %w", protoVersion(v6), err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.recs = records

	return nil
}
