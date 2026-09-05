// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leasehook implements a plugin that tells other systems what this
// server just handed out, over a webhook or a local program. Same idea as
// Kea's run_script hook and dnsmasq's dhcp-script: a way to feed an IPAM, an
// inventory or a monitoring pipeline without teaching it to read lease
// files.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - leasehook: url:https://ipam.example/hook secret:env:HOOK_SECRET timeout:2s queue:1000
//
//	server6:
//	  plugins:
//	    - leasehook: exec:/usr/local/bin/lease-event timeout:5s events:reply,release
//
// Exactly one of url: and exec: is required and says where events go. A URL
// has to be http or https. An exec path has to be absolute, so what runs does
// not depend on the server's working directory or on PATH.
//
// The rest is optional, may be given in any order, and each key may appear
// once. An argument that is not one of these fails setup by name rather than
// being ignored:
//
//   - secret:<value> or secret:env:<NAME> signs the webhook body. The env:
//     form reads the variable once, during setup, and fails when it is unset
//     or empty. It is the better form: the config loader prints every plugin's
//     arguments at startup, and while it replaces the value of a secret:
//     argument with ***, a secret that never enters the config file cannot
//     leak from it either. The key has no meaning in exec mode and is refused
//     there.
//   - timeout:<duration> bounds one delivery, default 2s.
//   - queue:<n> is the length of the event queue, default 1000.
//   - events:<name>,<name> restricts what is delivered to the named events.
//     The default is all of them.
//
// # Events
//
// An event is built from what the plugin can see at its position in the chain,
// which is why placement matters (see below). DHCPv4:
//
//   - offer, ack: the chain produced an OFFER or an ACK carrying an address.
//   - nak: the chain produced a NAK.
//   - release, decline: the client sent a RELEASE (the address is ciaddr) or a
//     DECLINE (the address is the one in option 50). The server answers
//     neither, but the chain still runs for both.
//
// DHCPv6:
//
//   - reply: the Reply carries at least one IA_NA address or IA_PD prefix.
//   - release, decline: the client is giving up or refusing what its own
//     message names.
//
// # Payload
//
// One JSON object per event, with the empty fields left out:
//
//	{
//	  "family": 4,
//	  "event": "ack",
//	  "time": "2026-09-05T12:00:00Z",
//	  "mac": "aa:bb:cc:dd:ee:ff",
//	  "duid": "00030001aabbccddeeff",
//	  "hostname": "laptop",
//	  "addresses": ["10.0.0.5/32"],
//	  "prefixes": ["2001:db8:1::/64"],
//	  "lease_seconds": 3600,
//	  "relay": "10.0.1.1",
//	  "transaction_id": "11223344"
//	}
//
// duid and prefixes only ever appear on DHCPv6 events. Addresses are written
// as host routes, /32 and /128, because a lease is one address: the subnet
// mask a DHCPv4 client is told to use is a separate option that any plugin in
// the chain may have set, and reporting it here would suggest the lease covers
// the whole subnet. relay carries giaddr on DHCPv4 and the link address of the
// relay closest to the client on DHCPv6.
//
// The hostname is whatever the client put in option 12, or in the DHCPv6 FQDN
// option, cut to 255 bytes. It is a JSON string like any other, so the encoder
// escapes it; a consumer still has to treat it as text a stranger chose.
//
// # Delivery
//
// The handler serialises the event, puts it on a buffered channel and returns.
// A single worker goroutine drains that channel in order. Nothing on the
// packet path ever waits for an HTTP round trip or a fork: a hook endpoint
// that has stopped answering slows down deliveries, not DHCP.
//
// When the queue is full the event is dropped and counted, and a line goes to
// the log at most once a minute. A server whose endpoint has stalled drops
// events by the thousand, and one line each would bury everything else.
//
// A webhook delivery is a POST with Content-Type: application/json, the
// signature header when a secret is configured, and no retries. A DHCP client
// that gets no answer retransmits and produces a fresh event; a redelivery
// queue would either grow without bound or reorder events, and an endpoint
// that has to see every one should acknowledge quickly and queue on its own
// side. A non-2xx answer is logged with its status.
//
// With a secret configured, every POST carries
//
//	X-Coredhcp-Signature: sha256=<hex HMAC-SHA256 of the exact request body>
//
// Verify it against the raw bytes with a constant-time comparison before
// parsing them.
//
// An exec delivery runs the program with no arguments, the JSON body on
// stdin, and these variables added to the server's environment:
// LEASEHOOK_EVENT, LEASEHOOK_FAMILY, LEASEHOOK_MAC, LEASEHOOK_ADDRESSES (space
// separated) and LEASEHOOK_HOSTNAME. Delegated prefixes are on stdin only. A
// non-zero exit is logged with the first kilobyte of stderr.
//
// # Security
//
// Every field of a DHCP packet is chosen by whoever sent it. Nothing from a
// packet is ever put on a command line: the program is executed directly, with
// no arguments and no shell, so a hostname full of metacharacters is only ever
// data. Control characters are replaced in the environment variables, because
// a NUL would stop the program from starting at all and an escape sequence
// would be acted on by whatever reads the script's output.
//
// # Placement
//
// List leasehook last, after every allocator. It reports what the response
// carries at the moment it runs, so a plugin further down that assigns the
// address, or changes the lease time, does so after the event was built. A
// plugin ahead of it that stops the chain hides those requests entirely.
//
// setup4 and setup6 build one instance each, so a server running both families
// has two queues and two workers. A DHCPv6 burst then cannot push DHCPv4
// events out of a shared queue.
package leasehook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/leasehook")

// Plugin wraps the leasehook plugin information.
var Plugin = plugins.Plugin{
	Name:   "leasehook",
	Setup6: setup6,
	Setup4: setup4,
}

const (
	// The accepted argument keys.
	urlArg     = "url:"
	execArg    = "exec:"
	secretArg  = "secret:"
	timeoutArg = "timeout:"
	queueArg   = "queue:"
	eventsArg  = "events:"

	// secretEnvPrefix marks a secret that names an environment variable
	// instead of carrying the value in config.yml.
	secretEnvPrefix = "env:"

	// Defaults for the optional arguments.
	defaultTimeout = 2 * time.Second
	defaultQueue   = 1000

	// dropWarnInterval is how often a full queue is worth a log line.
	dropWarnInterval = time.Minute

	// Accepted URL schemes.
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// settings is the parsed configuration.
type settings struct {
	url     string // request URL, empty in exec mode
	shown   string // the URL with any password redacted, for the log
	path    string // program to run, empty in webhook mode
	secret  []byte
	timeout time.Duration
	queue   int
	events  map[string]bool
}

// argParser is one accepted argument key and the function that reads its
// value.
type argParser struct {
	key   string
	apply func(*settings, string) error
}

// argParsers holds every accepted key, in the order they are documented. It
// is read only after initialization.
var argParsers = []argParser{
	{urlArg, applyURL},
	{execArg, applyExec},
	{secretArg, applySecret},
	{timeoutArg, applyTimeout},
	{queueArg, applyQueue},
	{eventsArg, applyEvents},
}

// parseArgs turns the config line into settings. The defaults go in first, so
// an argument only ever replaces one of them, and a key that appears twice is
// refused rather than silently overriding itself.
func parseArgs(args []string) (*settings, error) {
	s := &settings{timeout: defaultTimeout, queue: defaultQueue, events: knownEvents}
	seen := make(map[string]bool, len(args))
	for _, arg := range args {
		p, raw, err := parserFor(arg)
		if err != nil {
			return nil, err
		}
		if seen[p.key] {
			return nil, fmt.Errorf("%s given more than once", strings.TrimSuffix(p.key, ":"))
		}
		seen[p.key] = true
		if err := p.apply(s, raw); err != nil {
			return nil, err
		}
	}
	return s, validate(s)
}

// parserFor finds the parser for one argument and returns it along with the
// value that follows the key.
func parserFor(arg string) (argParser, string, error) {
	for _, p := range argParsers {
		if raw, ok := strings.CutPrefix(arg, p.key); ok {
			return p, raw, nil
		}
	}
	return argParser{}, "", fmt.Errorf("unknown argument %q, want one of %s", arg, knownArgs())
}

// knownArgs lists the accepted keys for an error message.
func knownArgs() string {
	keys := make([]string, 0, len(argParsers))
	for _, p := range argParsers {
		keys = append(keys, p.key+"<value>")
	}
	return strings.Join(keys, ", ")
}

// validate checks the combinations no single parser can see.
func validate(s *settings) error {
	switch {
	case s.url == "" && s.path == "":
		return fmt.Errorf("need one of %s<url> or %s<absolute path>", urlArg, execArg)
	case s.url != "" && s.path != "":
		return fmt.Errorf("%s and %s are mutually exclusive, events go to one place", urlArg, execArg)
	case len(s.secret) > 0 && s.url == "":
		return fmt.Errorf("%s signs the webhook body and has no meaning with %s", secretArg, execArg)
	}
	return nil
}

// applyURL reads the webhook URL.
//
// A parse failure is unwrapped down to its cause before it is reported,
// because net/url puts the whole URL in its error and the URL may carry a
// password.
func applyURL(s *settings, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return fmt.Errorf("unsupported URL scheme %q, want %s:// or %s://", u.Scheme, schemeHTTP, schemeHTTPS)
	}
	if u.Host == "" {
		return errors.New("webhook URL has no host")
	}
	s.url = u.String()
	s.shown = u.Redacted()
	return nil
}

// applyExec reads the program to run. Only an absolute path is accepted: a
// relative one would be resolved against whatever directory the server
// happens to have been started in.
func applyExec(s *settings, raw string) error {
	if !filepath.IsAbs(raw) {
		return fmt.Errorf("%s needs an absolute path, got %q", strings.TrimSuffix(execArg, ":"), raw)
	}
	s.path = filepath.Clean(raw)
	return nil
}

// applySecret takes the secret literally, or reads it from the environment
// for the env: form.
func applySecret(s *settings, raw string) error {
	name, fromEnv := strings.CutPrefix(raw, secretEnvPrefix)
	if !fromEnv {
		if raw == "" {
			return fmt.Errorf("%s needs a value", secretArg)
		}
		s.secret = []byte(raw)
		return nil
	}
	if name == "" {
		return fmt.Errorf("%s%s needs an environment variable name", secretArg, secretEnvPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return fmt.Errorf("environment variable %s is unset or empty", name)
	}
	s.secret = []byte(value)
	return nil
}

// applyTimeout sets the per-delivery timeout.
func applyTimeout(s *settings, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid %s%s: %w", timeoutArg, raw, err)
	}
	if d <= 0 {
		return fmt.Errorf("%s has to be positive, got %s", strings.TrimSuffix(timeoutArg, ":"), raw)
	}
	s.timeout = d
	return nil
}

// applyQueue sets the length of the event queue.
func applyQueue(s *settings, raw string) error {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return fmt.Errorf("invalid %s%s, want a positive number of events", queueArg, raw)
	}
	s.queue = n
	return nil
}

// applyEvents narrows the events that are delivered.
func applyEvents(s *settings, raw string) error {
	names := strings.Split(raw, ",")
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !knownEvents[name] {
			return fmt.Errorf("unknown event %q, want one of %s", name, eventNames())
		}
		allowed[name] = true
	}
	s.events = allowed
	return nil
}

// newTarget builds the delivery target these settings name.
func (s *settings) newTarget() target {
	if s.path != "" {
		return &command{path: s.path}
	}
	return newWebhook(s.url, s.secret)
}

// describe names the target for the log, without the secret and without any
// password the URL carries.
func (s *settings) describe() string {
	if s.path != "" {
		return s.path
	}
	return s.shown
}

// eventList renders the configured event names in the documented order.
func (s *settings) eventList() string {
	names := make([]string, 0, len(s.events))
	for _, name := range allEvents {
		if s.events[name] {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

// delivery is one queued event: the JSON body every target sends, and the
// event itself, which the exec target turns into environment variables.
type delivery struct {
	payload []byte
	ev      event
}

// pluginState is one configured instance of the plugin.
//
// It is safe for concurrent use. The handlers read only fields written during
// setup and send on queue; the drop bookkeeping has its own lock, which is
// taken on the drop path and nowhere else.
type pluginState struct {
	target  target
	queue   chan delivery
	events  map[string]bool
	timeout time.Duration

	// now is the clock seam, time.Now in production. It is written during
	// setup, before the worker starts, and only read afterwards. Use timeNow
	// rather than calling it directly: a zero-valued pluginState, which the
	// tests build, leaves it nil.
	now func() time.Time

	// stop closes to shut the worker down; done closes once it has exited.
	// The server never stops a plugin, so nothing closes stop in production.
	// It is here so a test does not leave a goroutine behind.
	stop chan struct{}
	done chan struct{}

	// dropMu guards drops, the number of events the queue had no room for,
	// and lastWarn, when that was last logged.
	dropMu   sync.Mutex
	drops    uint64
	lastWarn time.Time
}

func setup4(args ...string) (handler.Handler4, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

// setupState parses the arguments, builds the instance and starts its worker.
//
// Nothing is contacted here. A webhook that is down must not keep the DHCP
// server from starting, and a program that is missing shows up as a failed
// delivery on the first event rather than at boot.
func setupState(args ...string) (*pluginState, error) {
	s, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	p := newPluginState(s)
	go p.run()
	log.Infof("reporting %s to %s, queue %d, timeout %s", s.eventList(), s.describe(), s.queue, s.timeout)
	return p, nil
}

// newPluginState builds the instance without starting the worker, which is
// what a test wants when it drives deliveries by hand.
func newPluginState(s *settings) *pluginState {
	return &pluginState{
		target:  s.newTarget(),
		queue:   make(chan delivery, s.queue),
		events:  s.events,
		timeout: s.timeout,
		now:     time.Now,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// timeNow reads the clock through the seam, falling back to time.Now so a
// zero-valued pluginState still works.
func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// Handler4 reports DHCPv4 lease events and hands the response straight on.
//
// It never stops the chain and never touches the response, so adding it
// changes nothing but what other systems get told.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if ev, ok := event4(req, resp, p.timeNow()); ok {
		p.enqueue(ev)
	}
	return resp, false
}

// Handler6 reports DHCPv6 lease events and hands the response straight on.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if ev, ok := event6(req, resp, p.timeNow()); ok {
		p.enqueue(ev)
	}
	return resp, false
}

// marshalEvent serialises one event. It is a variable so the failure branch
// in enqueue, which encoding/json cannot reach for this struct, can still be
// exercised; the server package swaps sendEthernetFn the same way.
var marshalEvent = json.Marshal

// enqueue hands one event to the worker. It never blocks: a slow endpoint
// must not hold up the packet that produced the event.
func (p *pluginState) enqueue(ev event) {
	if !p.events[ev.Event] {
		return
	}
	payload, err := marshalEvent(ev)
	if err != nil {
		log.Errorf("BUG: could not serialise a %s event: %v", ev.Event, err)
		return
	}
	select {
	case p.queue <- delivery{payload: payload, ev: ev}:
	default:
		p.dropped()
	}
}

// dropped records one event the queue had no room for.
func (p *pluginState) dropped() {
	if total, warn := p.countDrop(); warn {
		log.Warningf("event queue is full, %d event(s) dropped so far", total)
	}
}

// countDrop counts the drop and reports whether it is time to log again.
func (p *pluginState) countDrop() (uint64, bool) {
	p.dropMu.Lock()
	defer p.dropMu.Unlock()
	p.drops++
	now := p.timeNow()
	if !p.lastWarn.IsZero() && now.Sub(p.lastWarn) < dropWarnInterval {
		return p.drops, false
	}
	p.lastWarn = now
	return p.drops, true
}

// run delivers queued events in order, one at a time, until stop is closed.
// Whatever is still queued at that point is discarded, which only happens in
// a test: nothing in the server stops a plugin.
func (p *pluginState) run() {
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case d := <-p.queue:
			p.deliverOne(d)
		}
	}
}

// deliverOne hands one event to the target, bounded by the configured
// timeout, and logs a failure. There is no retry; see the delivery section of
// the package documentation.
func (p *pluginState) deliverOne(d delivery) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	if err := p.target.deliver(ctx, d); err != nil {
		log.Errorf("delivering the %s event failed: %v", d.ev.Event, err)
	}
}

// stopWorker shuts the worker down and waits for it to exit. Nothing in the
// server calls this; it is here so a test does not leak a goroutine.
func (p *pluginState) stopWorker() {
	close(p.stop)
	<-p.done
}
