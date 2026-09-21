// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/netbox")

// Plugin wraps the netbox plugin information.
//
// Both setup functions are the context-aware form, so a lookup on the request
// path inherits the caller's deadline and is cancelled at shutdown.
var Plugin = plugins.Plugin{
	Name:      "netbox",
	Setup6Ctx: setup6,
	Setup4Ctx: setup4,
}

// Defaults for the optional trailing arguments.
const (
	defaultTTL         = 5 * time.Minute
	defaultNegativeTTL = 30 * time.Second
	defaultTimeout     = 5 * time.Second
	defaultLifetime    = time.Hour
)

// options holds the tunable durations, filled in from the trailing arguments.
type options struct {
	ttl         time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	lifetime    time.Duration
}

// durationOptions maps each trailing argument prefix to its default and the
// field it sets.
// Adding a knob here is all it takes; parseOne stays a loop either way.
var durationOptions = []struct {
	prefix string
	def    time.Duration
	set    func(*options, time.Duration)
}{
	{"ttl:", defaultTTL, func(o *options, d time.Duration) { o.ttl = d }},
	{"negative-ttl:", defaultNegativeTTL, func(o *options, d time.Duration) { o.negativeTTL = d }},
	{"timeout:", defaultTimeout, func(o *options, d time.Duration) { o.timeout = d }},
	{"lifetime:", defaultLifetime, func(o *options, d time.Duration) { o.lifetime = d }},
}

// defaultOptions returns the options as they stand before any argument is read.
func defaultOptions() options {
	return options{
		ttl:         defaultTTL,
		negativeTTL: defaultNegativeTTL,
		timeout:     defaultTimeout,
		lifetime:    defaultLifetime,
	}
}

// parse applies the trailing arguments in order.
func (o *options) parse(args []string) error {
	for _, arg := range args {
		if err := o.parseOne(arg); err != nil {
			return err
		}
	}
	return nil
}

// parseOne applies a single trailing argument.
func (o *options) parseOne(arg string) error {
	for _, opt := range durationOptions {
		raw, ok := strings.CutPrefix(arg, opt.prefix)
		if !ok {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("the duration in %q does not parse: %w; use a Go duration such as 5m, or leave %s out for the default of %s",
				arg, err, opt.prefix, opt.def)
		}
		if d <= 0 {
			return fmt.Errorf("the duration in %q is not positive; use a duration above zero, or leave %s out for the default of %s",
				arg, opt.prefix, opt.def)
		}
		opt.set(o, d)
		return nil
	}
	return fmt.Errorf("unexpected argument %q; use one of %s each followed by a duration, and give the NetBox URL and token first",
		arg, knownOptions())
}

// knownOptions lists the accepted trailing argument prefixes for error
// messages, in the order they are documented.
func knownOptions() string {
	names := make([]string, 0, len(durationOptions))
	for _, opt := range durationOptions {
		names = append(names, opt.prefix)
	}
	return strings.Join(names, ", ")
}

// lookuper is the NetBox side of the plugin, as the handlers need it. It is
// declared here, where it is used, so the handler tests can drive every branch
// with a stub instead of an HTTP server.
type lookuper interface {
	lookup(ctx context.Context, mac string) (lookupResult, error)
}

// pluginState is one configured instance of the plugin. setup4 and setup6
// build one each, so a server that runs both families keeps a cache per
// family rather than sharing one across them.
//
// It is safe for concurrent use: the cache does its own locking, the backend
// is stateless, and everything else is written during setup and only read
// afterwards.
type pluginState struct {
	backend lookuper
	cache   *cache
	opts    options
	now     func() time.Time // clock seam, time.Now in production
}

func setup4(args ...string) (handler.Handler4Ctx, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6Ctx, error) {
	p, err := setupState(args...)
	if err != nil {
		return nil, err
	}
	return p.Handler6, nil
}

// setupState validates the arguments and builds an instance.
//
// It deliberately does not contact NetBox. A DHCP server has to come up when
// NetBox is down or still booting, and the first request will find out soon
// enough whether the credentials work.
func setupState(args ...string) (*pluginState, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("got %d argument(s); give the NetBox URL and the API token first, as in https://netbox.example.com token:env:NETBOX_TOKEN",
			len(args))
	}
	base, err := parseBaseURL(args[0])
	if err != nil {
		return nil, err
	}
	token, err := resolveToken(args[1])
	if err != nil {
		return nil, err
	}
	opts := defaultOptions()
	if err := opts.parse(args[2:]); err != nil {
		return nil, err
	}

	log.Infof("using NetBox at %s, caching answers for %s and misses for %s, request timeout %s",
		base, opts.ttl, opts.negativeTTL, opts.timeout)

	return &pluginState{
		backend: newClient(base, token, opts.timeout),
		cache:   newCache(maxCacheEntries),
		opts:    opts,
		now:     time.Now,
	}, nil
}

// lookup answers from the cache when it can, and asks NetBox otherwise.
// Errors are returned as they are and never cached, so a NetBox that was
// briefly unreachable is retried on the next packet instead of being
// remembered as a failure for a whole TTL.
//
// The configured timeout bounds the miss path as a whole: both backend calls
// a cold lookup makes, not each one separately.
//
// There is no single-flight around the miss path. Two packets from the same
// client arriving while the first lookup is still out will both query NetBox,
// which is two requests for one client rather than the coordination and the
// extra lock a de-duplicating layer costs. A boot storm is many clients, and
// those are separate lookups either way.
func (p *pluginState) lookup(ctx context.Context, hwaddr net.HardwareAddr) (lookupResult, error) {
	mac := hwaddr.String()
	now := p.now()
	if result, ok := p.cache.get(mac, now); ok {
		return result, nil
	}

	ctx, cancel := context.WithTimeout(ctx, p.opts.timeout)
	defer cancel()
	result, err := p.backend.lookup(ctx, mac)
	if err != nil && !errors.Is(err, ErrNoInterface) {
		return lookupResult{}, err
	}
	// ErrNoInterface is an answer, not a failure, and is cached for the
	// negative TTL.

	ttl := p.opts.ttl
	if !result.found {
		ttl = p.opts.negativeTTL
	}
	p.cache.put(mac, result, now.Add(ttl))
	return result, nil
}

// skipsLookup4 reports whether msgType never needs a NetBox lookup. INFORM
// carries no address request. RELEASE and DECLINE are skipped too: the
// server never replies to either whatever the plugin chain returns, this
// plugin holds no lease state that a release could free, and looking them up
// anyway would let a spoofed MAC turn every DECLINE it sends into a NetBox
// API call.
func skipsLookup4(msgType dhcpv4.MessageType) bool {
	switch msgType {
	case dhcpv4.MessageTypeInform, dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// logLookupFailure logs ErrUnauthorized and ErrNotFound at error level, since
// every packet fails the same way until an operator fixes the configuration.
// Anything else is likely transient and the client's retransmission retries
// it, so it gets a warning. Either way the request is dropped.
func logLookupFailure(mac net.HardwareAddr, err error) {
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) {
		log.Errorf("dropping the request from MAC address %s, the NetBox lookup keeps failing until the configuration is fixed: %v", mac, err)
		return
	}
	log.Warningf("dropping the request from MAC address %s, the NetBox lookup failed: %v; the client retransmits and the lookup is retried then", mac, err)
}

// Handler4 handles DHCPv4 packets for the netbox plugin.
func (p *pluginState) Handler4(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if skipsLookup4(req.MessageType()) {
		return resp, false
	}

	result, err := p.lookup(ctx, req.ClientHWAddr)
	if err != nil {
		logLookupFailure(req.ClientHWAddr, err)
		return nil, true
	}
	if !result.found || !result.v4.IsValid() {
		log.Infof("MAC address %s has no IPv4 address in NetBox", req.ClientHWAddr)
		return resp, false
	}

	resp.YourIPAddr = result.v4.Addr().AsSlice()
	resp.Options.Update(dhcpv4.OptSubnetMask(net.CIDRMask(result.v4.Bits(), 32)))
	log.Infof("MAC address %s given IP address %s", req.ClientHWAddr, result.v4)
	return resp, true
}

// skipsLookup6 reports whether msgType never needs a NetBox lookup, for the
// same reasons as skipsLookup4: RELEASE and DECLINE get no reply and free no
// state this plugin holds.
func skipsLookup6(msgType dhcpv6.MessageType) bool {
	switch msgType {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// Handler6 handles DHCPv6 packets for the netbox plugin.
func (p *pluginState) Handler6(ctx context.Context, req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate the DHCPv6 request, dropping it: %v; please report this with the log line", err)
		return nil, true
	}

	// A relayed message carries the client's own type inside; the relay
	// wrapper's type is RELAY-FORW or RELAY-REPL and says nothing about
	// what the client sent, so the check runs on m, not req.
	if skipsLookup6(m.MessageType) {
		return resp, false
	}

	iana := m.Options.OneIANA()
	if iana == nil {
		log.Debug("No address requested")
		return resp, false
	}

	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		log.Infof("Could not find client MAC for %s, passing", req)
		return resp, false
	}

	result, err := p.lookup(ctx, mac)
	if err != nil {
		logLookupFailure(mac, err)
		return nil, true
	}
	if !result.found || !result.v6.IsValid() {
		log.Infof("MAC address %s has no IPv6 address in NetBox", mac)
		return resp, false
	}

	resp.AddOption(&dhcpv6.OptIANA{
		IaId: iana.IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          result.v6.Addr().AsSlice(),
				PreferredLifetime: p.opts.lifetime,
				ValidLifetime:     p.opts.lifetime,
			},
		}},
	})
	log.Infof("MAC address %s given IP address %s", mac, result.v6)
	return resp, false
}
