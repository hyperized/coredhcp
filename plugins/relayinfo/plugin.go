// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package relayinfo hands out addresses by the port a request came in on
// instead of by the client that sent it.
//
// A relay stamps every request with the port it arrived on: circuit-id,
// remote-id or subscriber-id inside the DHCPv4 relay agent information option
// (option 82, RFC 3046 and RFC 3993), interface-id or remote-id among the
// DHCPv6 relay options (RFC 8415 section 21.18 and RFC 4649). This plugin
// maps those values to fixed addresses read from a text file, so a
// subscriber's address follows the wire they are plugged into and survives
// the modem being swapped for one with a different MAC.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - relayinfo: file:/etc/coredhcp/ports.txt key:circuit-id allow 10.0.1.1 10.0.2.0/24 autorefresh
//
// The named arguments may be given in any order. The allow list is the
// exception: its addresses follow the allow keyword, so anything after it
// that is not a named argument is read as an address. Anything else fails
// setup by name.
//
//   - file:<path> is the mapping file, required. A relative path is resolved
//     against the working directory coredhcp was started in.
//   - key:<name> is the piece of relay information to match on, required.
//     server4 accepts circuit-id, remote-id and subscriber-id (option 82
//     sub-options 1, 2 and 6); server6 accepts interface-id and remote-id
//     (options 18 and 37). A name from the other family fails setup.
//   - allow <addr|cidr>... names the relays whose relay information this
//     instance will act on, and is required. It is spelled the way the relay
//     plugin spells it. At least one entry has to be of the family the
//     section serves, since an allow list that cannot match anything admits
//     nothing.
//   - autorefresh reloads the file whenever it changes on disk. Without it
//     the file is read once, at startup.
//
// The plugin is configured per family, so a dual-stack server that wants both
// needs a relayinfo entry in server4 and another in server6, each with its
// own file and its own allow list.
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
// A request whose key is in the file is answered with the address mapped to
// it. On DHCPv4 the plugin sets yiaddr and the lease time and ends the chain,
// the way the file plugin does, so plugins that add options belong before it.
// On DHCPv6 it adds an IA_NA for the IAID the client asked with and lets the
// chain continue.
//
// Anything else is passed on untouched: a request with no relay information,
// one whose key is not in the file, one whose key is longer than 255 bytes,
// and DHCPv4 RELEASE, DECLINE and INFORM along with DHCPv6 Release and
// Decline.
//
// The enterprise number of a DHCPv6 remote-id is not part of the key, only
// the identifier bytes after it.
//
// # Trusting the relay
//
// Nothing in the protocol authenticates relay information. On a segment where
// an untrusted device can reach the server directly, a client can send an
// option 82 of its own making, and a server that believes it hands that
// client whichever address it asked for.
//
// The allow list is what closes that. A request presenting relay information
// (option 82 or a giaddr on DHCPv4, a Relay-forward on DHCPv6) has the source
// address of its datagram matched against the configured prefixes before the
// mapping is read, and is dropped when it came from anywhere else. A relayed
// request the server could not attribute at all is dropped too.
//
// A request presenting no relay information is passed to the next plugin
// untouched, so a section serving on-link clients alongside relayed ones
// keeps answering the on-link ones.
//
// That is a filter and not authentication. A host sharing a segment with a
// trusted relay can still source packets from the relay's address if nothing
// on the switch stops it; port security, DHCP snooping and IP source guard
// are what hold that ground.
//
// # Placement
//
// A dropped request ends the chain, so no later plugin answers it either.
// Only a request carrying relay information is ever dropped. Drops are logged
// at Info with the source address, at most one line per second per reason.
package relayinfo

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

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

	// allowArg is spelled the way the relay plugin spells it, so the two read
	// alike in a config file.
	allowArg = "allow"

	// maxKeyLen bounds the key taken off the wire. An option 82 sub-option
	// cannot exceed it, its length being a single byte.
	maxKeyLen = 255

	logInterval = time.Second
)

var log = logger.GetLogger("plugins/relayinfo")

// Plugin wraps the relayinfo plugin information.
//
// Both families use the context-aware setup functions because the allow list
// matches on the datagram's source address, which exists nowhere in the DHCP
// payload.
var Plugin = plugins.Plugin{
	Name:      "relayinfo",
	Setup6Ctx: setup6,
	Setup4Ctx: setup4,
}

// Setup errors callers and tests can match with errors.Is. Errors that quote
// the offending argument are built with fmt.Errorf instead.
var (
	errNoFile         = errors.New("need a mapping file, as file:<path>")
	errNoKey          = errors.New("need a key to match on, as key:<name>")
	errNoAllow        = errors.New("need a relay allow list, `allow` followed by addresses or prefixes")
	errNoAllowEntries = errors.New("need at least one address or prefix after `allow`")
	errMappedEntry    = errors.New("IPv4-mapped IPv6 entry never matches, write it as a plain IPv4 address")
	errZonedEntry     = errors.New("zoned address never matches, the interface is matched separately")
)

// fsnotifyNewWatcher and watcherAdd are indirections tests substitute to
// simulate a watcher that fails to initialize or attach, which no real
// filesystem operation triggers deterministically.
var (
	fsnotifyNewWatcher = fsnotify.NewWatcher
	watcherAdd         = (*fsnotify.Watcher).Add
)

// keyFunc4 returns nil when the request does not carry the configured relay
// option, which is distinct from one that is present and empty.
type keyFunc4 func(*dhcpv4.DHCPv4) []byte

// keyFunc6 is keyFunc4 for the outermost relay of a DHCPv6 request.
type keyFunc6 func(*dhcpv6.RelayMessage) []byte

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

// reason names one cause for dropping a request. Every value is a constant,
// which is what keeps the drop limiter's map bounded by the set below rather
// than by the traffic it sees.
type reason string

const (
	reasonNoRequestInfo  reason = "no request information"
	reasonPeerNotAllowed reason = "relay source not in the allow list"
)

// dropLimiter holds back repeated drop log lines, one per reason per
// logInterval.
type dropLimiter struct {
	// now is a field so tests can step over the interval instead of sleeping
	// through it.
	now func() time.Time

	mu   sync.Mutex
	last map[reason]time.Time
}

func newDropLimiter(now func() time.Time) *dropLimiter {
	return &dropLimiter{now: now, last: make(map[reason]time.Time)}
}

func (l *dropLimiter) allow(r reason) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if prev, ok := l.last[r]; ok && t.Sub(prev) < logInterval {
		return false
	}
	l.last[r] = t
	return true
}

// pluginState holds the key -> address mapping backing one instance of the
// plugin. setupState creates one per call, so the server4 and server6 entries
// of a dual-stack configuration keep their mappings apart.
//
// Exactly one of extract4 and extract6 is set. That, keyName and allow are
// fixed at setup time and read without the lock, which only guards recs.
type pluginState struct {
	mu   sync.RWMutex
	recs map[string]record

	keyName  string
	extract4 keyFunc4
	extract6 keyFunc6
	allow    []netip.Prefix
	limiter  *dropLimiter
}

func (s *pluginState) numRecords() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recs)
}

func (s *pluginState) logDrop(r reason, format string, args ...any) {
	if !s.limiter.allow(r) {
		return
	}
	log.Infof("dropping request (%s): %s", r, fmt.Sprintf(format, args...))
}

// fromAllowedRelay fails closed: a request that arrives without the server's
// description of it cannot be attributed to a relay at all.
func (s *pluginState) fromAllowedRelay(ctx context.Context) bool {
	info, ok := handler.RequestInfoFrom(ctx)
	if !ok {
		s.logDrop(reasonNoRequestInfo, "cannot tell where the request came from")
		return false
	}
	// Unmapping means an IPv4 peer read off a dual-stack socket compares equal
	// to the same address written in dotted-quad form in the configuration.
	peer := info.Peer.Addr().Unmap()
	if !slices.ContainsFunc(s.allow, func(p netip.Prefix) bool { return p.Contains(peer) }) {
		s.logDrop(reasonPeerNotAllowed, "source %s", peer)
		return false
	}
	return true
}

// match logs every reason it passes a request on, since from the outside they
// all look the same: the plugin did nothing.
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

// passthrough4 leaves a message alone when INFORM asks for options only, or
// when a client releases or declines an address a static mapping never had to
// reclaim.
func passthrough4(mt dhcpv4.MessageType) bool {
	return mt == dhcpv4.MessageTypeInform ||
		mt == dhcpv4.MessageTypeRelease ||
		mt == dhcpv4.MessageTypeDecline
}

// relayed4 reports whether a DHCPv4 request presents relay information, by
// carrying an option 82 or by naming a relay in giaddr.
func relayed4(req *dhcpv4.DHCPv4) bool {
	return req.RelayAgentInfo() != nil || giaddrSet(req.GatewayIPAddr)
}

// giaddrSet reports whether giaddr names a relay. An unset field reaches us
// as nil, as four zero bytes, or as 0.0.0.0 in 16-byte form.
func giaddrSet(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && !addr.Unmap().IsUnspecified()
}

// Handler4 handles DHCPv4 packets for the relayinfo plugin.
func (s *pluginState) Handler4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if !relayed4(req) {
		log.Debug("request carries no relay information, passing")
		return resp, false
	}
	if !s.fromAllowedRelay(ctx) {
		return nil, true
	}
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
func (s *pluginState) Handler6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	// The key comes out of the outermost relay, the one closest to the server:
	// with relays chained that is the aggregation device, and its options are
	// the ones the operator provisions against.
	relay, isRelay := req.(*dhcpv6.RelayMessage)
	if !isRelay {
		log.Debug("request did not come through a relay, passing")
		return resp, false
	}
	if !s.fromAllowedRelay(ctx) {
		return nil, true
	}
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

func setup4(args ...string) (handler.Handler4Ctx, error) {
	s, err := setupState(false, args...)
	if err != nil {
		return nil, err
	}
	return s.Handler4, nil
}

func setup6(args ...string) (handler.Handler6Ctx, error) {
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

	allow4 []netip.Prefix
	allow6 []netip.Prefix

	// sawAllow records that the keyword itself was given, which is what turns
	// a bare argument from a typo into an allow list entry.
	sawAllow bool
}

// parseArgs makes an unrecognised argument an error naming it, so that a typo
// fails the server at startup instead of quietly disabling autorefresh.
func parseArgs(args []string) (pluginArgs, error) {
	var a pluginArgs
	for _, arg := range args {
		if err := a.apply(arg); err != nil {
			return a, err
		}
	}
	switch {
	case a.filename == "":
		return a, errNoFile
	case a.key == "":
		return a, errNoKey
	case !a.sawAllow:
		return a, errNoAllow
	}
	return a, nil
}

// apply treats a bare argument as an allow list entry only once the allow
// keyword has been seen; before that it is the typo it looks like.
func (a *pluginArgs) apply(arg string) error {
	if a.applyNamed(arg) {
		return nil
	}
	if a.sawAllow {
		return a.addAllowEntry(arg)
	}
	return fmt.Errorf("unexpected argument `%s`, want %s<path>, %s<name>, %s <addr|cidr>... or %s",
		arg, fileArgPrefix, keyArgPrefix, allowArg, autoRefreshArg)
}

// applyNamed reports whether arg was one of the named arguments.
func (a *pluginArgs) applyNamed(arg string) bool {
	switch {
	case arg == autoRefreshArg:
		a.refresh = true
	case arg == allowArg:
		a.sawAllow = true
	case strings.HasPrefix(arg, fileArgPrefix):
		a.filename = strings.TrimPrefix(arg, fileArgPrefix)
	case strings.HasPrefix(arg, keyArgPrefix):
		a.key = strings.TrimPrefix(arg, keyArgPrefix)
	default:
		return false
	}
	return true
}

func (a *pluginArgs) addAllowEntry(arg string) error {
	prefix, err := parseAllowEntry(arg)
	if err != nil {
		return err
	}
	if prefix.Addr().Is4() {
		a.allow4 = append(a.allow4, prefix)
		return nil
	}
	a.allow6 = append(a.allow6, prefix)
	return nil
}

// allowFor drops the other family's entries rather than refusing them, so one
// line can be copied between the two server sections and still mean what it
// reads as.
func (a *pluginArgs) allowFor(v6 bool) []netip.Prefix {
	if v6 {
		return a.allow6
	}
	return a.allow4
}

// parseAllowEntry turns one argument into a prefix, a bare address becoming a
// host prefix so that both forms compare the same way afterwards.
//
// An IPv4-mapped IPv6 entry and a zoned address are refused rather than
// quietly ignored: netip never matches the first against an unmapped address,
// and the server strips the zone before a plugin sees the peer, so both would
// look configured and admit nothing.
func parseAllowEntry(arg string) (netip.Prefix, error) {
	if strings.Contains(arg, "/") {
		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", arg, err)
		}
		if prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("prefix %q: %w", arg, errMappedEntry)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(arg)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q: %w", arg, err)
	}
	if addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("address %q: %w", arg, errMappedEntry)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("address %q: %w", arg, errZonedEntry)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// keySource resolves a configured key name against one family's key table.
func keySource[F any](family, name string, allowed map[string]F) (F, error) {
	fn, ok := allowed[name]
	if !ok {
		var zero F
		return zero, fmt.Errorf("unknown %s key `%s`, want one of %s",
			family, name, strings.Join(slices.Sorted(maps.Keys(allowed)), ", "))
	}
	return fn, nil
}

func familyName(v6 bool) string {
	if v6 {
		return "DHCPv6"
	}
	return "DHCPv4"
}

// setupState loads the mapping file once during setup, so a broken file fails
// startup rather than the first request.
func setupState(v6 bool, args ...string) (*pluginState, error) {
	a, err := parseArgs(args)
	if err != nil {
		return nil, err
	}

	s := &pluginState{
		keyName: a.key,
		allow:   a.allowFor(v6),
		limiter: newDropLimiter(time.Now),
	}
	if len(s.allow) == 0 {
		return nil, fmt.Errorf("%w for %s", errNoAllowEntries, familyName(v6))
	}
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

	log.Infof("loaded %d %s mappings from %s, allowing %d relay source(s)",
		s.numRecords(), a.key, a.filename, len(s.allow))
	return s, nil
}

// watch goes on the directory rather than on the file: a mapping file is
// usually replaced by renaming a new one over the old, and a watch on the file
// follows the inode that was renamed away, so every update after the first
// would be missed.
func (s *pluginState) watch(v6 bool, filename string) error {
	watcher, err := fsnotifyNewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	dir := filepath.Dir(filename)
	if err = watcherAdd(watcher, dir); err != nil {
		return fmt.Errorf("failed to watch %s: %w", dir, err)
	}

	go s.watchLoop(v6, filename, watcher)
	return nil
}

// watchLoop runs until the watcher is closed, which nothing does: a plugin is
// set up once and lives as long as the process.
//
// Both channels have to be read. fsnotify sends errors on an unbuffered
// channel and blocks until somebody takes one, so a loop that only ranges over
// Events parks fsnotify's own reader on the first error and no further event
// ever arrives. An error reloads as well, since a live watch reports one when
// events were dropped, a full inotify queue being the usual cause.
func (s *pluginState) watchLoop(v6 bool, filename string, watcher *fsnotify.Watcher) {
	base := filepath.Base(filename)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Watching the directory reports every file in it.
			if filepath.Base(event.Name) != base {
				continue
			}
			s.refresh(v6, filename)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Warningf("watch on %s reported an error: %s", filename, err)
			s.refresh(v6, filename)
		}
	}
}

// refresh keeps the mapping already loaded when the reread fails, so a file
// caught halfway through being written does not empty the server's idea of the
// network.
func (s *pluginState) refresh(v6 bool, filename string) {
	if err := s.loadFromFile(v6, filename); err != nil {
		log.Warningf("failed to refresh from %s: %s", filename, err)
		return
	}
	log.Infof("updated to %d mappings from %s", s.numRecords(), filename)
}

// loadFromFile builds the new map before taking the write lock, so a failed
// parse leaves the old one in place.
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
