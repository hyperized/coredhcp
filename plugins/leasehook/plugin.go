// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

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
			return nil, fmt.Errorf("%s given more than once; keep one %s<value> on the leasehook line and remove the rest",
				strings.TrimSuffix(p.key, ":"), p.key)
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
	return argParser{}, "", fmt.Errorf("unknown argument %q; use one of %s", arg, knownArgs())
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
		return fmt.Errorf("no destination for the events; add %s<url> for a webhook or %s<absolute path> for a program to run", urlArg, execArg)
	case s.url != "" && s.path != "":
		return fmt.Errorf("%s and %s cannot both be set, events go to one place; remove whichever of the two you do not want", urlArg, execArg)
	case len(s.secret) > 0 && s.url == "":
		return fmt.Errorf("%s signs the webhook body and has no meaning with %s; remove the secret, or send to %s<url> instead", secretArg, execArg, urlArg)
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
		if uerr, ok := errors.AsType[*url.Error](err); ok {
			err = uerr.Err
		}
		return fmt.Errorf("the webhook URL does not parse: %w; write it as %s%s://host/path or %s%s://host/path", err, urlArg, schemeHTTP, urlArg, schemeHTTPS)
	}
	if u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return fmt.Errorf("unsupported URL scheme %q in the webhook URL; use %s:// or %s://", u.Scheme, schemeHTTP, schemeHTTPS)
	}
	if u.Host == "" {
		return errors.New("the webhook URL has no host; write it as url:https://host/path, with the host straight after the scheme")
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
		return fmt.Errorf("%s needs an absolute path, got %q; give the full path, such as /usr/local/bin/lease-event", strings.TrimSuffix(execArg, ":"), raw)
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
			return fmt.Errorf("%s needs a value; use %s%sHOOK_SECRET to read it from the environment and keep it out of config.yml",
				secretArg, secretArg, secretEnvPrefix)
		}
		s.secret = []byte(raw)
		return nil
	}
	if name == "" {
		return fmt.Errorf("%s%s needs an environment variable name; use %s%sHOOK_SECRET and export it before starting coredhcp",
			secretArg, secretEnvPrefix, secretArg, secretEnvPrefix)
	}
	value := os.Getenv(name)
	if value == "" {
		return fmt.Errorf("environment variable %s is unset or empty; export it with the webhook secret before starting coredhcp", name)
	}
	s.secret = []byte(value)
	return nil
}

// applyTimeout sets the per-delivery timeout.
func applyTimeout(s *settings, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("timeout %q is not a duration: %w; use a Go duration such as 2s or 500ms, or leave it out for the default of %s",
			raw, err, defaultTimeout)
	}
	if d <= 0 {
		return fmt.Errorf("timeout %q is not positive; use a duration above zero such as 2s, or leave it out for the default of %s", raw, defaultTimeout)
	}
	s.timeout = d
	return nil
}

// applyQueue sets the length of the event queue.
func applyQueue(s *settings, raw string) error {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return fmt.Errorf("queue %q is not a positive number of events; use a whole number such as 1000, or leave it out for the default of %d",
			raw, defaultQueue)
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
			return fmt.Errorf("unknown event %q; use a comma-separated list of %s, or leave %s out for all of them", name, eventNames(), eventsArg)
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
		log.Errorf("BUG: could not serialise a %s event, so it was dropped: %v; please report this with the log line", ev.Event, err)
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
		log.Warningf("the event queue is full and %d event(s) have been dropped; check that the hook keeps up, or raise queue: above %d",
			total, cap(p.queue))
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
		log.Errorf("delivering the %s event failed and it is not retried: %v; check the hook target and the configured timeout", d.ev.Event, err)
	}
}

// stopWorker shuts the worker down and waits for it to exit. Nothing in the
// server calls this; it is here so a test does not leak a goroutine.
func (p *pluginState) stopWorker() {
	close(p.stop)
	<-p.done
}
