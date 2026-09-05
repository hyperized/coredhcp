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
// The two optional arguments may be given in either order:
//
//	autorefresh   reload the mapping whenever the lease file changes.
//	key:<mode>    what the first field of a lease line holds: 'mac' (the default,
//	              accepted by both families), 'duid' (server6 only) or
//	              'client-id' (server4 only).
//
// An argument that is neither fails setup by name.
//
// # Lookup key
//
// 'key:duid' matches the DUID as it goes on the wire, two-octet type code included, written in
// hexadecimal with an optional 0x prefix and optional colons. It is the mode to use when clients
// identify with a DUID-EN or DUID-UUID, which carry no link-layer address to key a MAC on. These
// three lines name the same client:
//
//	0x00030001aabbccddeeff 2001:db8::10:1
//	00:03:00:01:aa:bb:cc:dd:ee:ff 2001:db8::10:1
//	00030001AABBCCDDEEFF 2001:db8::10:1
//
// A DUID is at most 130 octets: RFC 8415 section 11.1 caps it at 128 and the type code is two
// more. A longer one is a setup error, and a request carrying one is passed to the next plugin.
//
// 'key:client-id' matches the raw bytes of option 61. RFC 2132 section 9.14 puts a type octet
// first: type 1 is a hardware address, and an RFC 4361 client puts a DUID behind type 255.
// Everything else is opaque, and an identifier that reads as text takes a 'text:' prefix:
//
//	0x01aabbccddeeff 10.0.0.1
//	01:aa:bb:cc:dd:ee:ff 10.0.0.1
//	text:printer-2nd-floor 10.0.0.2
//
// A 'text:' value cannot contain whitespace, because lines are split on it. A client that sends
// no option 61 at all is passed to the next plugin.
//
// For DHCPv4 `server4`, the file plugin must come after any general plugins needed, e.g. dns or
// router. The order is unimportant for DHCPv6, but affects the order of options in the response.
//
// RELEASE and DECLINE are ignored: static mappings have no lease to reclaim.
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

// Test seams: real filesystem operations cannot make fsnotify fail to
// initialize or attach deterministically.
var (
	fsnotifyNewWatcher = fsnotify.NewWatcher
	watcherAdd         = (*fsnotify.Watcher).Add
)

type options struct {
	filename    string
	autorefresh bool
	mode        keyMode
}

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

// setupFile builds one instance per call, so using the plugin on both server4
// and server6 keeps the two lease sets independent.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]netip.Addr

	// Set during setup, read-only afterwards.
	name   string
	family uint8
	// What recs is keyed on. Set before the handlers or the autorefresh
	// goroutine exist, and read without the lock after that.
	mode keyMode
}

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

// A Reply to a Release or Decline must not hand the address back, whatever
// reservation the client has.
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

// An INFORM asks for options only, and a static reservation has nothing to
// free on a release or a decline.
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

	if err := s.loadFromFile(v6, opts.filename); err != nil {
		return nil, nil, err
	}

	if opts.autorefresh {
		if err := s.watchFile(v6, opts.filename); err != nil {
			return nil, nil, err
		}
	}

	// Last, once everything that could fail has succeeded: a lease reader
	// must never find a half-built instance in the registry.
	leases.Register(s)
	log.Infof("loaded %d leases from %s", s.numRecords(), opts.filename)
	return s.Handler6, s.Handler4, nil
}

// A reload that fails keeps the leases already loaded: a file caught half
// written is a poor reason to stop answering the clients that are in it.
func (s *pluginState) watchFile(v6 bool, filename string) error {
	watcher, err := fsnotifyNewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	if err := watcherAdd(watcher, filename); err != nil {
		return fmt.Errorf("failed to watch %s: %w", filename, err)
	}

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
