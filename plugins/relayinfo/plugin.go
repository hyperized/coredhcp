// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package relayinfo hands out addresses by the port a request came in on
// instead of by the client that sent it.
//
// A switch or BNG that relays DHCP stamps every request with the port it
// arrived on: circuit-id, remote-id or subscriber-id inside the DHCPv4 relay
// agent information option (option 82, RFC 3046 and RFC 3993), interface-id
// or remote-id among the DHCPv6 relay options (RFC 8415 section 21.18 and
// RFC 4649). This plugin maps those values to fixed addresses read from a
// text file, so a subscriber's address follows the wire they are plugged
// into and survives the modem being swapped for one with a different MAC.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - relayinfo: file:/etc/coredhcp/ports.txt key:circuit-id autorefresh
//
// Arguments may be given in any order. Anything that is not one of the three
// below fails setup by name.
//
//   - file:<path> is the mapping file, required. A relative path is resolved
//     against the working directory coredhcp was started in.
//   - key:<name> is the piece of relay information to match on, required.
//     server4 accepts circuit-id, remote-id and subscriber-id (option 82
//     sub-options 1, 2 and 6); server6 accepts interface-id and remote-id
//     (options 18 and 37). The two lists are separate, and a name from the
//     other family fails setup.
//   - autorefresh reloads the file whenever it changes on disk. Without it
//     the file is read once, at startup.
//
// The plugin is configured per family, so a dual-stack server that wants both
// needs a relayinfo entry in server4 and another in server6, each with its
// own file.
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
// The key value is matched against the raw bytes the relay sent, and can be
// written two ways. As text it is printable ASCII with no whitespace, which
// covers the human-readable circuit-ids most switches produce. As hex it is
// "0x" followed by an even number of hex digits, for the binary forms (a
// DOCSIS remote-id is six raw bytes of MAC, and Cisco's default circuit-id is
// a packed VLAN and port number). A key that really does start with the two
// characters "0x" has to be written in the hex form, and so does one
// containing a '#', since the comment is stripped first.
//
// The lease is optional and takes any duration time.ParseDuration accepts,
// with a resolution of one second. It becomes the DHCPv4 lease time (option
// 51) or both DHCPv6 lifetimes for that one mapping, and defaults to 1h.
//
// The address has to be of the family the section serves. Two lines mapping
// the same key, or the same address, are both accepted with a warning: the
// last line wins, which is not usually what was meant.
//
// # Behaviour
//
// The plugin answers a request whose key is in the file with the address
// mapped to it. On DHCPv4 it sets yiaddr and the lease time and ends the
// chain, the way the file plugin does, so plugins that add options belong
// before it. On DHCPv6 it adds an IA_NA for the IAID the client asked with
// and lets the chain continue, since option order in the response is up to
// the plugins that follow.
//
// Anything else is passed on untouched: a request with no relay information,
// one whose key is not in the file, and one whose key is longer than 255
// bytes. That bound is what an option 82 sub-option can hold anyway (its
// length is one byte), and it keeps a relay that stuffs a 64KB interface-id
// into every packet from turning each request into a large map lookup.
// DHCPv4 RELEASE, DECLINE and INFORM, and DHCPv6 Release and Decline, are
// passed on as well. The mapping is static, so there is nothing to reclaim
// when a client gives an address up, and INFORM asks for options only.
//
// The enterprise number of a DHCPv6 remote-id is not part of the key, only
// the identifier bytes after it. A relay fleet uses one enterprise number
// throughout, and carrying it in the file would make every line quote a
// vendor code that never varies.
//
// # Trusting the relay
//
// Nothing in the protocol authenticates relay information. On a segment where
// an untrusted device can reach the server directly, every byte of it is
// under the client's control: a client can send an option 82 of its own
// making, and a server that believes it hands that client whichever address
// it asked for. Two things have to hold before this plugin is worth
// deploying.
//
// The relay has to be the only path to the server. Restrict the listening
// address, filter DHCP at the network edge, or put the server on a network
// only relays can reach. RFC 3046 section 2.1 says a relay agent discards a
// request that already carries an option 82 from a downstream port, and most
// switches do that by default, but that only helps for requests that actually
// pass through the relay.
//
// The relay's own address has to be checked, which this plugin does not do.
// Pair it with a plugin or a firewall that admits only known relay addresses.
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

	// maxKeyLen bounds the key taken off the wire. An option 82 sub-option
	// cannot exceed this anyway, and a DHCPv6 interface-id that does is not
	// something an operator writes down in a mapping file.
	maxKeyLen = 255
)

var log = logger.GetLogger("plugins/relayinfo")

// Plugin wraps the relayinfo plugin information.
var Plugin = plugins.Plugin{
	Name:   "relayinfo",
	Setup6: setup6,
	Setup4: setup4,
}

// Setup errors that callers and tests can match with errors.Is. Errors that
// have to quote the offending argument are built with fmt.Errorf instead.
var (
	errNoFile = errors.New("need a mapping file, as file:<path>")
	errNoKey  = errors.New("need a key to match on, as key:<name>")
)

// fsnotifyNewWatcher and watcherAdd are indirections over the two fsnotify
// calls autorefresh needs. Production code always uses the real
// implementations assigned here; tests substitute them to simulate the
// watcher failing to initialize or attach, which real filesystem operations
// cannot trigger deterministically.
var (
	fsnotifyNewWatcher = fsnotify.NewWatcher
	watcherAdd         = (*fsnotify.Watcher).Add
)

// keyFunc4 pulls the configured relay option out of a DHCPv4 request. It
// returns nil when the request does not carry it, which is distinct from an
// option that is present and empty.
type keyFunc4 func(*dhcpv4.DHCPv4) []byte

// keyFunc6 is keyFunc4 for the outermost relay of a DHCPv6 request.
type keyFunc6 func(*dhcpv6.RelayMessage) []byte

// keys4 and keys6 are the allow-lists behind the key: argument. They differ
// per family because the two protocols carry different relay options, and a
// name is only ever looked up in the list for the family being set up.
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

// relaySubOption builds the extractor for one option 82 sub-option.
func relaySubOption(code dhcpv4.OptionCode) keyFunc4 {
	return func(req *dhcpv4.DHCPv4) []byte {
		info := req.RelayAgentInfo()
		if info == nil {
			return nil
		}
		return info.Get(code)
	}
}

// pluginState holds the key -> address mapping backing one instance of the
// plugin, and the lock protecting it against the autorefresh goroutine.
// setupState creates one instance per call, so the server4 and server6
// entries of a dual-stack configuration keep their mappings apart.
//
// Exactly one of extract4 and extract6 is set, the one for the family this
// instance was set up for. Both are fixed at setup time and read without the
// lock, which only guards recs.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]record

	keyName  string
	extract4 keyFunc4
	extract6 keyFunc6
}

// numRecords returns the number of currently loaded mappings.
func (s *pluginState) numRecords() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recs)
}

// match looks up a key taken off the wire. It rejects a missing or oversized
// key before the map is touched, and logs the reason a request is passed on,
// since from the outside every one of these looks the same: the plugin did
// nothing.
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

// passthrough4 reports whether a DHCPv4 message has to be left alone. INFORM
// asks for options only, and a static mapping has nothing to reclaim when a
// client releases or declines an address. The server sends no reply to the
// last two at all.
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

	// The request as handed to the plugin is the outermost relay, the one
	// closest to the server. With relays chained, that is the aggregation
	// device rather than the access switch the client is plugged into, and
	// its options are the ones the operator provisions against.
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

// pluginArgs is the parsed argument list.
type pluginArgs struct {
	filename string
	key      string
	refresh  bool
}

// parseArgs picks the file, the key and the autorefresh flag out of the
// argument list, in whatever order they were given. An argument that is none
// of the three is an error naming it, so that a typo fails the server at
// startup instead of quietly disabling autorefresh.
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

// keySource resolves a configured key name against one family's allow-list.
// The error lists the names that would have worked, because the two families
// accept different ones and remote-id is the only name they share.
func keySource[F any](family, name string, allowed map[string]F) (F, error) {
	fn, ok := allowed[name]
	if !ok {
		var zero F
		return zero, fmt.Errorf("unknown %s key `%s`, want one of %s",
			family, name, strings.Join(slices.Sorted(maps.Keys(allowed)), ", "))
	}
	return fn, nil
}

// setupState builds one plugin instance: it validates the arguments, loads
// the mapping file once so a broken file fails startup, and starts the
// autorefresh watcher if it was asked for.
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

// watch reloads the mapping file on every event fsnotify reports for it. A
// reload that fails keeps the mapping that was already loaded, so a file
// caught halfway through being written does not empty the server's idea of
// the network.
//
// The goroutine runs until the watcher is closed, which nothing does: a
// plugin is set up once and lives as long as the process, and the file plugin
// watches its lease file the same way.
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

// loadFromFile reads the mapping file and swaps it in under the write lock.
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
