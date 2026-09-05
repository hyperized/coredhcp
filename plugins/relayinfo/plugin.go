// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package relayinfo hands out addresses by the port a request came in on,
// not by the client that sent it.
//
// A relay stamps every request with the port it arrived on: circuit-id,
// remote-id or subscriber-id in the DHCPv4 relay agent information option
// (RFC 3046, RFC 3993), or interface-id or remote-id among the DHCPv6 relay
// options (RFC 8415 section 21.18, RFC 4649). This plugin maps those values
// to fixed addresses read from a text file, so a subscriber's address
// follows the wire it is plugged into rather than the modem's MAC.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - relayinfo: file:/etc/coredhcp/ports.txt key:circuit-id autorefresh
//
// Arguments may be given in any order; anything else fails setup by name.
//
//   - file:<path> is the mapping file, required. A relative path resolves
//     against the working directory coredhcp was started in.
//   - key:<name> is the relay information to match on, required. server4
//     accepts circuit-id, remote-id and subscriber-id (option 82
//     sub-options 1, 2 and 6); server6 accepts interface-id and remote-id
//     (options 18 and 37) - the two lists are separate.
//   - autorefresh reloads the file whenever it changes on disk; without it
//     the file is read once, at startup.
//
// A dual-stack server needs a relayinfo entry in both server4 and server6,
// each with its own file.
//
// # File format
//
// One mapping per line, `<key value> <ip> [lease]`, and anything from a '#'
// to the end of the line is a comment:
//
//	# port 3 on the access switch in rack 4
//	rack4-sw1:eth3   192.0.2.31    24h
//	0x0004010203     192.0.2.32                 # same, written as raw bytes
//	docsis-cm-0042   192.0.2.33                 # inherits the 1h default
//
// The key value is matched against the raw bytes the relay sent, written
// either as text (printable ASCII, no whitespace) or, for binary forms like
// a DOCSIS remote-id or a packed VLAN/port circuit-id, as "0x" followed by
// an even number of hex digits. A key starting with "0x", or containing a
// '#', has to use the hex form, since the comment is stripped first.
//
// The lease is optional, takes any duration time.ParseDuration accepts, and
// defaults to 1h; it becomes the DHCPv4 lease time (option 51) or both
// DHCPv6 lifetimes for that mapping. The address has to be of the family the
// section serves. Two lines mapping the same key or address are both
// accepted with a warning: the last line wins.
//
// # Behaviour
//
// The plugin answers a request whose key is in the file with the mapped
// address. On DHCPv4 it sets yiaddr and the lease time and ends the chain,
// the way the file plugin does, so plugins that add options belong before
// it. On DHCPv6 it adds an IA_NA for the client's IAID and lets the chain
// continue, since option order is up to the plugins that follow.
//
// Anything else passes on untouched: no relay information, a key not in the
// file, or a key over 255 bytes - the largest an option 82 sub-option can
// hold, and a bound against a relay stuffing a large interface-id into every
// packet. DHCPv4 RELEASE, DECLINE and INFORM, and DHCPv6 Release and
// Decline, pass on too: the mapping is static, so there is nothing to
// reclaim, and INFORM asks for options only.
//
// A DHCPv6 remote-id's enterprise number is not part of the key, only the
// identifier bytes after it - a relay fleet uses one enterprise number
// throughout, so carrying it would make every line quote a code that never
// varies.
//
// # Trusting the relay
//
// Nothing in the protocol authenticates relay information: on a segment
// where an untrusted device can reach the server directly, a client can send
// an option 82 of its own making and receive whichever address it asks for.
// Two things have to hold before this plugin is worth deploying.
//
// The relay has to be the only path to the server: restrict the listening
// address, filter DHCP at the network edge, or put the server on a
// relay-only network. RFC 3046 section 2.1 has a relay agent discard a
// request that already carries option 82 from a downstream port, but that
// only helps for requests that actually pass through the relay.
//
// The relay's own address has to be checked, which this plugin does not do;
// pair it with a plugin or a firewall that admits only known relay addresses.
package relayinfo

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

const (
	autoRefreshArg = "autorefresh"
	fileArgPrefix  = "file:"
	keyArgPrefix   = "key:"

	// An option 82 sub-option cannot exceed this anyway, and a DHCPv6
	// interface-id that does is not something an operator writes into a mapping file.
	maxKeyLen = 255
)

var log = logger.GetLogger("plugins/relayinfo")

// Plugin wraps the relayinfo plugin information.
var Plugin = plugins.Plugin{
	Name:   "relayinfo",
	Setup6: setup6,
	Setup4: setup4,
}

// Matched with errors.Is; an error that has to quote the offending argument
// is built with fmt.Errorf instead.
var (
	errNoFile = errors.New("need a mapping file, as file:<path>")
	errNoKey  = errors.New("need a key to match on, as key:<name>")
)

// Indirections over fsnotify so tests can simulate the watcher failing to
// initialize or attach - not reliably triggerable with real filesystem calls.
var (
	fsnotifyNewWatcher = fsnotify.NewWatcher
	watcherAdd         = (*fsnotify.Watcher).Add
)

// Returns nil when the request doesn't carry the option - distinct from present-but-empty.
type keyFunc4 func(*dhcpv4.DHCPv4) []byte

type keyFunc6 func(*dhcpv6.RelayMessage) []byte

// Differ per family: the two protocols carry different relay options, and a
// name is only looked up in the list for the family being set up.
var (
	keys4 = map[string]keyFunc4{
		"circuit-id":    relaySubOption(dhcpv4.AgentCircuitIDSubOption),
		"remote-id":     relaySubOption(dhcpv4.AgentRemoteIDSubOption),
		"subscriber-id": relaySubOption(dhcpv4.SubscriberIDSubOption),
	}
	keys6 = map[string]keyFunc6{
		"interface-id": func(relay *dhcpv6.RelayMessage) []byte {
			return relay.Options.InterfaceID()
		},
		"remote-id": func(relay *dhcpv6.RelayMessage) []byte {
			opt := relay.Options.RemoteID()
			if opt == nil {
				return nil
			}
			return opt.RemoteID
		},
	}
)

func relaySubOption(code dhcpv4.OptionCode) keyFunc4 {
	return func(req *dhcpv4.DHCPv4) []byte {
		info := req.RelayAgentInfo()
		if info == nil {
			return nil
		}
		return info.Get(code)
	}
}

// One instance per setup call keeps server4 and server6 mappings apart.
// Exactly one of extract4/extract6 is set, fixed at setup and read lock-free; the lock only guards recs.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]record

	keyName  string
	extract4 keyFunc4
	extract6 keyFunc6
}

func (s *pluginState) numRecords() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recs)
}

// Rejects a missing or oversized key before touching the map, logging why -
// from outside, every case looks like the plugin doing nothing.
func (s *pluginState) match(key []byte) (record, bool) {
	switch {
	case key == nil:
		log.Debugf("request carries no %s, passing", s.keyName)
		return record{}, false
	case len(key) > maxKeyLen:
		log.Debugf("%s is %d bytes, over the %d byte limit, passing", s.keyName, len(key), maxKeyLen)
		return record{}, false
	}

	s.mu.RLock()
	rec, ok := s.recs[string(key)]
	s.mu.RUnlock()

	if !ok {
		log.Debugf("%s %s is not mapped, passing", s.keyName, keyText(string(key)))
	}
	return rec, ok
}

// INFORM asks for options only; a static mapping has nothing to reclaim on
// RELEASE/DECLINE, which get no reply anyway.
func passthrough4(mt dhcpv4.MessageType) bool {
	return mt == dhcpv4.MessageTypeInform ||
		mt == dhcpv4.MessageTypeRelease ||
		mt == dhcpv4.MessageTypeDecline
}

// Handler4 handles DHCPv4 packets for the relayinfo plugin.
func (s *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if passthrough4(req.MessageType()) {
		return resp, false
	}
	key := s.extract4(req)
	rec, ok := s.match(key)
	if !ok {
		return resp, false
	}

	resp.YourIPAddr = rec.addr.AsSlice()
	resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(rec.lease))
	log.Infof("%s %s given IP address %s for %s", s.keyName, keyText(string(key)), rec.addr, rec.lease)
	return resp, true
}

// Handler6 handles DHCPv6 packets for the relayinfo plugin.
func (s *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate: %v", err)
		return nil, true
	}

	// A Reply to a Release or Decline must not hand the address back to the
	// client, so skip the IA_NA regardless of what the client asked for.
	if m.MessageType == dhcpv6.MessageTypeRelease || m.MessageType == dhcpv6.MessageTypeDecline {
		return resp, false
	}
	iana := m.Options.OneIANA()
	if iana == nil {
		log.Debug("no address requested, passing")
		return resp, false
	}

	// req is the outermost relay - closest to the server, not the access switch
	// the client is plugged into - so its options are what the operator provisions against.
	relay, ok := req.(*dhcpv6.RelayMessage)
	if !ok {
		log.Debug("request did not come through a relay, passing")
		return resp, false
	}
	key := s.extract6(relay)
	rec, ok := s.match(key)
	if !ok {
		return resp, false
	}

	resp.AddOption(&dhcpv6.OptIANA{
		IaId: iana.IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          rec.addr.AsSlice(),
				PreferredLifetime: rec.lease,
				ValidLifetime:     rec.lease,
			},
		}},
	})
	log.Infof("%s %s given IP address %s for %s", s.keyName, keyText(string(key)), rec.addr, rec.lease)
	return resp, false
}

func setup4(args ...string) (handler.Handler4, error) {
	s, err := setupState(false, args...)
	if err != nil {
		return nil, err
	}
	return s.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	s, err := setupState(true, args...)
	if err != nil {
		return nil, err
	}
	return s.Handler6, nil
}

type pluginArgs struct {
	filename string
	key      string
	refresh  bool
}

// An unrecognized argument errors by name, so a typo fails startup instead
// of quietly disabling autorefresh.
func parseArgs(args []string) (pluginArgs, error) {
	var a pluginArgs
	for _, arg := range args {
		switch {
		case arg == autoRefreshArg:
			a.refresh = true
		case strings.HasPrefix(arg, fileArgPrefix):
			a.filename = strings.TrimPrefix(arg, fileArgPrefix)
		case strings.HasPrefix(arg, keyArgPrefix):
			a.key = strings.TrimPrefix(arg, keyArgPrefix)
		default:
			return a, fmt.Errorf("unexpected argument `%s`, want %s<path>, %s<name> or %s",
				arg, fileArgPrefix, keyArgPrefix, autoRefreshArg)
		}
	}
	if a.filename == "" {
		return a, errNoFile
	}
	if a.key == "" {
		return a, errNoKey
	}
	return a, nil
}

// The error lists the names that would have worked; the two families accept
// different ones, and remote-id is the only one they share.
func keySource[F any](family, name string, allowed map[string]F) (F, error) {
	fn, ok := allowed[name]
	if !ok {
		var zero F
		return zero, fmt.Errorf("unknown %s key `%s`, want one of %s",
			family, name, strings.Join(slices.Sorted(maps.Keys(allowed)), ", "))
	}
	return fn, nil
}

// Loads the file once here so a broken mapping fails startup, before
// autorefresh (if requested) takes over.
func setupState(v6 bool, args ...string) (*pluginState, error) {
	a, err := parseArgs(args)
	if err != nil {
		return nil, err
	}

	s := &pluginState{keyName: a.key}
	if v6 {
		s.extract6, err = keySource("DHCPv6", a.key, keys6)
	} else {
		s.extract4, err = keySource("DHCPv4", a.key, keys4)
	}
	if err != nil {
		return nil, err
	}

	if err = s.loadFromFile(v6, a.filename); err != nil {
		return nil, err
	}
	if a.refresh {
		if err = s.watch(v6, a.filename); err != nil {
			return nil, err
		}
	}

	log.Infof("loaded %d %s mappings from %s", s.numRecords(), a.key, a.filename)
	return s, nil
}

// A failed reload keeps the mapping already loaded, so a file caught
// mid-write doesn't empty the server's view. The goroutine runs until the process exits.
func (s *pluginState) watch(v6 bool, filename string) error {
	watcher, err := fsnotifyNewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	if err = watcherAdd(watcher, filename); err != nil {
		return fmt.Errorf("failed to watch %s: %w", filename, err)
	}

	go func() {
		for range watcher.Events {
			if err := s.loadFromFile(v6, filename); err != nil {
				log.Warningf("failed to refresh from %s: %s", filename, err)
				continue
			}
			log.Infof("updated to %d mappings from %s", s.numRecords(), filename)
		}
	}()
	return nil
}

// The new map is built first, so a failed parse leaves the old one in place.
func (s *pluginState) loadFromFile(v6 bool, filename string) error {
	records, err := loadRecords(filename, v6)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = records
	return nil
}
