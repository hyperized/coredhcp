// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package netbox implements a plugin that answers from NetBox: it looks up the
// requesting MAC address in a NetBox instance and hands out the addresses
// documented on the interface that carries it.
//
// Configure it with the NetBox URL and an API token:
//
//	server4/server6:
//	  plugins:
//	    - netbox: https://netbox.example.com env:NETBOX_TOKEN ttl:5m
//
// The URL is the root of the NetBox installation, with or without a subpath
// (https://netbox.example.com or https://host/netbox); the plugin appends
// /api/... to it. Only http and https are accepted.
//
// The token is either the token itself or env:NAME, which reads it from the
// environment when the server starts. Setup fails when that variable is unset
// or empty. Tokens starting with "nbt_" are the v2 tokens NetBox 4.5
// introduced and are sent as "Authorization: Bearer"; everything else is sent
// as "Authorization: Token". NetBox deprecated the legacy tokens in 4.6 and
// plans to drop them in 5.0, so new deployments should be issuing v2 tokens
// already. This plugin never logs the token, and the config loader keeps it
// out of its own output too: at the default level it prints each plugin's
// name and argument count, and the arguments themselves only at debug level,
// with anything shaped like a token, password or secret replaced by ***.
// Recognising a bare token by its shape is a safety net rather than a
// guarantee, so env:NAME stays the better way to configure it.
//
// The remaining arguments are optional and may appear in any order:
//
//   - ttl:<duration> how long a found answer is cached, default 5m.
//   - negative-ttl:<duration> how long "NetBox does not know this MAC" is
//     cached, default 30s.
//   - timeout:<duration> the HTTP timeout per NetBox request, default 5s.
//   - lifetime:<duration> the preferred and valid lifetime of the DHCPv6
//     address, default 1h.
//
// Every duration must be positive, and an argument that is none of the above
// fails setup naming itself, rather than being quietly ignored.
//
// # What it asks NetBox
//
// Two calls per cache miss. First /api/dcim/mac-addresses/ filtered on the
// MAC, which yields the interface the address is assigned to, on a device or
// on a virtual machine. Then /api/ipam/ip-addresses/ filtered on that
// interface with status=active, from which the first IPv4 and the first IPv6
// address are taken in the order NetBox returns them.
//
// This needs NetBox 4.2 or newer, where MAC addresses became a model of their
// own. The token needs read access to dcim.macaddress and ipam.ipaddress and
// nothing else.
//
// The addresses come from the interface the MAC sits on, not from the device
// the interface belongs to. On a machine with more than one NIC the device's
// primary_ip4/primary_ip6 belongs to a single interface, and the client that
// just sent a DISCOVER is not necessarily on that one. Filtering by interface
// also covers virtual machines, since NetBox stores VM interface addresses in
// the same place. The abandoned upstream plugin did neither: it read the
// device's primary addresses and ignored virtual machines.
//
// # Caching
//
// DHCP clients retransmit, and a site coming back from a power cut sends every
// client at once. The cache is what keeps that off NetBox: results are held in
// a bounded LRU keyed by MAC address, so a boot storm costs one API call per
// client rather than one per packet. Failures are never cached, so a NetBox
// that was briefly down is retried on the next packet.
//
// # Placement
//
// Same as the file plugin: after the option plugins (dns, router, netmask) and
// before range, so a documented client gets its NetBox address and everything
// else falls through to the dynamic pool.
//
// A failed lookup drops the request rather than passing it on. A client whose
// static address is documented in NetBox must not be handed a pool address by
// the next plugin because NetBox was briefly unreachable. The client
// retransmits, and gets its documented address once NetBox answers again.
//
// # TLS
//
// The system trust store, plus SSL_CERT_FILE or SSL_CERT_DIR for an internal
// CA. There is deliberately no option to skip verification. Every request
// carries the API token, so an unverified connection hands that token to
// whoever happens to answer on the address.
package netbox

import (
	"context"
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
var Plugin = plugins.Plugin{
	Name:   "netbox",
	Setup6: setup6,
	Setup4: setup4,
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

// durationOptions maps each trailing argument prefix to the field it sets.
// Adding a knob here is all it takes; parseOne stays a loop either way.
var durationOptions = []struct {
	prefix string
	set    func(*options, time.Duration)
}{
	{"ttl:", func(o *options, d time.Duration) { o.ttl = d }},
	{"negative-ttl:", func(o *options, d time.Duration) { o.negativeTTL = d }},
	{"timeout:", func(o *options, d time.Duration) { o.timeout = d }},
	{"lifetime:", func(o *options, d time.Duration) { o.lifetime = d }},
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
			return fmt.Errorf("invalid duration in argument %q: %w", arg, err)
		}
		if d <= 0 {
			return fmt.Errorf("duration in argument %q has to be positive", arg)
		}
		opt.set(o, d)
		return nil
	}
	return fmt.Errorf("unexpected argument %q, want %s followed by a duration", arg, knownOptions())
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

// setupState validates the arguments and builds an instance.
//
// It deliberately does not contact NetBox. A DHCP server has to come up when
// NetBox is down or still booting, and the first request will find out soon
// enough whether the credentials work.
func setupState(args ...string) (*pluginState, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("need at least 2 arguments (NetBox URL and API token), got %d", len(args))
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
// There is no single-flight around the miss path. Two packets from the same
// client arriving while the first lookup is still out will both query NetBox,
// which is two requests for one client rather than the coordination and the
// extra lock a de-duplicating layer costs. A boot storm is many clients, and
// those are separate lookups either way.
func (p *pluginState) lookup(hwaddr net.HardwareAddr) (lookupResult, error) {
	mac := hwaddr.String()
	now := p.now()
	if result, ok := p.cache.get(mac, now); ok {
		return result, nil
	}

	// The plugin handler API has no context to inherit, and the client's own
	// timeout bounds the request, so a background context is the whole story
	// here.
	result, err := p.backend.lookup(context.Background(), mac)
	if err != nil {
		return lookupResult{}, err
	}

	ttl := p.opts.ttl
	if !result.found {
		ttl = p.opts.negativeTTL
	}
	p.cache.put(mac, result, now.Add(ttl))
	return result, nil
}

// Handler4 handles DHCPv4 packets for the netbox plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.MessageType() == dhcpv4.MessageTypeInform {
		return resp, false
	}

	result, err := p.lookup(req.ClientHWAddr)
	if err != nil {
		log.Warningf("dropping request from MAC address %s, NetBox lookup failed: %v", req.ClientHWAddr, err)
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

// Handler6 handles DHCPv6 packets for the netbox plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate: %v", err)
		return nil, true
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

	result, err := p.lookup(mac)
	if err != nil {
		log.Warningf("dropping request from MAC address %s, NetBox lookup failed: %v", mac, err)
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
