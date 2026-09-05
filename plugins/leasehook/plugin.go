// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package leasehook implements a plugin that tells other systems what this
// server just handed out, over a webhook or a local program.
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
// Exactly one of url: (http or https) or exec: (an absolute path) is
// required. Optional, in any order, each key at most once:
//
//   - secret:<value> or secret:env:<NAME>: signs the webhook body; env:
//     keeps it out of the config file. Refused with exec:.
//   - timeout:<duration>: per-delivery bound, default 2s.
//   - queue:<n>: event queue length, default 1000.
//   - events:<name>,<name>: restrict delivery to these events, default all.
//
// # Events
//
// DHCPv4: offer, ack, nak, release, decline. DHCPv6: reply, release,
// decline. release and decline fire even though the server sends no answer.
//
// # Payload
//
// One JSON object per event, with empty fields omitted:
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
// duid and prefixes are DHCPv6-only. Addresses are host routes (/32, /128),
// not the client's subnet. relay is giaddr on DHCPv4, or the nearest relay's
// link address on DHCPv6. hostname is attacker-controlled text, cut to 255
// bytes.
//
// # Delivery
//
// Async and best-effort: a full queue drops the event, and there are no
// retries. A webhook POST carries, when a secret is configured,
//
//	X-Coredhcp-Signature: sha256=<hex HMAC-SHA256 of the exact request body>
//
// verified with a constant-time comparison against the raw body. An exec
// delivery gets the JSON on stdin plus LEASEHOOK_EVENT, LEASEHOOK_FAMILY,
// LEASEHOOK_MAC, LEASEHOOK_ADDRESSES (space separated) and
// LEASEHOOK_HOSTNAME in its environment.
//
// # Security
//
// Every packet field is attacker-controlled. Nothing from a packet reaches a
// command line, and control characters in environment variables are
// replaced with underscores.
//
// # Placement
//
// List leasehook last, after every allocator, so it reports what the chain
// finally assigned.
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
	urlArg     = "url:"
	execArg    = "exec:"
	secretArg  = "secret:"
	timeoutArg = "timeout:"
	queueArg   = "queue:"
	eventsArg  = "events:"

	secretEnvPrefix = "env:"

	defaultTimeout = 2 * time.Second
	defaultQueue   = 1000

	dropWarnInterval = time.Minute

	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

type settings struct {
	url     string // request URL, empty in exec mode
	shown   string // the URL with any password redacted, for the log
	path    string // program to run, empty in webhook mode
	secret  []byte
	timeout time.Duration
	queue   int
	events  map[string]bool
}

type argParser struct {
	key   string
	apply func(*settings, string) error
}

// Read only after initialization.
var argParsers = []argParser{
	{urlArg, applyURL},
	{execArg, applyExec},
	{secretArg, applySecret},
	{timeoutArg, applyTimeout},
	{queueArg, applyQueue},
	{eventsArg, applyEvents},
}

// Defaults go in first, so an argument only ever replaces one of them, and a
// key given twice is refused rather than silently overriding itself.
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

func parserFor(arg string) (argParser, string, error) {
	for _, p := range argParsers {
		if raw, ok := strings.CutPrefix(arg, p.key); ok {
			return p, raw, nil
		}
	}
	return argParser{}, "", fmt.Errorf("unknown argument %q, want one of %s", arg, knownArgs())
}

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

// A parse failure is unwrapped down to its cause before it is reported: the
// raw net/url error embeds the whole URL, which may carry a password.
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

// Only an absolute path is accepted: a relative one would resolve against
// whatever directory the server happens to have been started in.
func applyExec(s *settings, raw string) error {
	if !filepath.IsAbs(raw) {
		return fmt.Errorf("%s needs an absolute path, got %q", strings.TrimSuffix(execArg, ":"), raw)
	}
	s.path = filepath.Clean(raw)
	return nil
}

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

func applyQueue(s *settings, raw string) error {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return fmt.Errorf("invalid %s%s, want a positive number of events", queueArg, raw)
	}
	s.queue = n
	return nil
}

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

func (s *settings) newTarget() target {
	if s.path != "" {
		return &command{path: s.path}
	}
	return newWebhook(s.url, s.secret)
}

// Excludes the secret, and any password the URL carries.
func (s *settings) describe() string {
	if s.path != "" {
		return s.path
	}
	return s.shown
}

// Iterates allEvents, not the map, so the order matches the docs and stays deterministic.
func (s *settings) eventList() string {
	names := make([]string, 0, len(s.events))
	for _, name := range allEvents {
		if s.events[name] {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

// ev is kept alongside payload because the exec target also derives its
// environment variables from the struct, not from the JSON bytes.
type delivery struct {
	payload []byte
	ev      event
}

// Safe for concurrent use: the handlers only read fields written during
// setup and send on queue; the drop bookkeeping has its own lock, taken on
// the drop path and nowhere else.
type pluginState struct {
	target  target
	queue   chan delivery
	events  map[string]bool
	timeout time.Duration

	// Clock seam, written once before the worker starts. Use timeNow, not
	// this field directly: a zero-valued pluginState, as tests build, leaves it nil.
	now func() time.Time

	// Test seam: the server never stops a plugin, so nothing closes stop in
	// production; this exists so a test doesn't leak a goroutine.
	stop chan struct{}
	done chan struct{}

	// Guards drops and lastWarn.
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

// Nothing is contacted here: a webhook that is down must not keep the DHCP
// server from starting, and a missing program surfaces as a failed delivery
// on the first event rather than at boot.
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

// Does not start the worker, which is what a test wants when it drives deliveries by hand.
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

func (p *pluginState) timeNow() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// Handler4 reports DHCPv4 lease events without touching the chain or response.
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

// A variable, not a direct call, so enqueue's error branch — otherwise
// unreachable for this struct — can be exercised in tests.
var marshalEvent = json.Marshal

// Never blocks: a slow endpoint must not hold up the packet that produced the event.
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

func (p *pluginState) dropped() {
	if total, warn := p.countDrop(); warn {
		log.Warningf("event queue is full, %d event(s) dropped so far", total)
	}
}

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

// Anything still queued when stop closes is discarded; that only happens in
// a test, since nothing in the server stops a plugin.
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

func (p *pluginState) deliverOne(d delivery) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	if err := p.target.deliver(ctx, d); err != nil {
		log.Errorf("delivering the %s event failed: %v", d.ev.Event, err)
	}
}

// Nothing in the server calls this; it exists so a test does not leak a goroutine.
func (p *pluginState) stopWorker() {
	close(p.stop)
	<-p.done
}
