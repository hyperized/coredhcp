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
//	    - netbox: https://netbox.example.com token:env:NETBOX_TOKEN ttl:5m
//
// The URL is the root of the NetBox installation, with or without a subpath
// (https://netbox.example.com or https://host/netbox); the plugin appends
// /api/... to it. Only http and https are accepted.
//
// The token is best given as token:env:NAME, which reads NAME from the
// environment at startup and marks the argument as a secret; token:<value>
// and the older env:NAME and bare forms also work. A token starting with
// "nbt_" is a NetBox 4.5 v2 token and is sent as "Authorization: Bearer",
// everything else as "Authorization: Token".
//
// The remaining arguments are optional and may appear in any order:
//
//   - ttl:<duration> how long a found answer is cached, default 5m.
//   - negative-ttl:<duration> how long an unknown MAC is cached, default 30s.
//   - timeout:<duration> the HTTP timeout per NetBox request, default 5s.
//   - lifetime:<duration> the DHCPv6 address lifetime, default 1h.
//
// Every duration must be positive, and an argument that is none of the above
// fails setup naming itself.
//
// # What it asks NetBox
//
// Two calls per cache miss: /api/dcim/mac-addresses/ filtered on the MAC gives
// the interface it is assigned to, then /api/ipam/ip-addresses/ filtered on
// that interface with status=active gives the first IPv4 and IPv6 address in
// the order NetBox returns them.
//
// This needs NetBox 4.2 or newer, where MAC addresses became a model of their
// own, and a token with read access to dcim.macaddress and ipam.ipaddress.
//
// Addresses come from the interface, not from the device: on a multi-NIC
// machine primary_ip4/primary_ip6 belongs to one interface and the client that
// sent the DISCOVER need not be on it. Filtering by interface also covers
// virtual machines, whose addresses NetBox stores in the same place.
//
// # Caching
//
// Results are held in a bounded LRU keyed by MAC, so a site coming back from a
// power cut costs one API call per client rather than one per retransmission.
// Failures are never cached.
//
// # Placement
//
// Same as the file plugin: after the option plugins (dns, router, netmask) and
// before range. A failed lookup drops the request rather than passing it on,
// so a client documented in NetBox is never handed a pool address because
// NetBox was briefly unreachable; it retransmits and gets its own address.
//
// # TLS
//
// The system trust store, plus SSL_CERT_FILE or SSL_CERT_DIR for an internal
// CA. There is no option to skip verification: every request carries the API
// token, so an unverified connection hands it to whoever answers.
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

type options struct {
	ttl         time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	lifetime    time.Duration
}

var durationOptions = []struct {
	prefix string
	set    func(*options, time.Duration)
}{
	{"ttl:", func(o *options, d time.Duration) { o.ttl = d }},
	{"negative-ttl:", func(o *options, d time.Duration) { o.negativeTTL = d }},
	{"timeout:", func(o *options, d time.Duration) { o.timeout = d }},
	{"lifetime:", func(o *options, d time.Duration) { o.lifetime = d }},
}

func defaultOptions() options {
	return options{
		ttl:         defaultTTL,
		negativeTTL: defaultNegativeTTL,
		timeout:     defaultTimeout,
		lifetime:    defaultLifetime,
	}
}

func (o *options) parse(args []string) error {
	for _, arg := range args {
		if err := o.parseOne(arg); err != nil {
			return err
		}
	}
	return nil
}

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

func knownOptions() string {
	names := make([]string, 0, len(durationOptions))
	for _, opt := range durationOptions {
		names = append(names, opt.prefix)
	}
	return strings.Join(names, ", ")
}

// Declared where it is consumed, so the handler tests can drive every branch
// with a stub instead of an HTTP server.
type lookuper interface {
	lookup(ctx context.Context, mac string) (lookupResult, error)
}

// setup4 and setup6 build one each, so a server running both families keeps a
// cache per family. Safe for concurrent use: the cache locks itself, the
// backend is stateless, and the rest is write-once during setup.
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

// Deliberately does not contact NetBox: a DHCP server has to come up while
// NetBox is down or still booting.
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

// Errors are never cached, so a NetBox that was briefly unreachable is retried
// on the next packet. There is deliberately no single-flight: a boot storm is
// many clients, which are separate lookups either way.
func (p *pluginState) lookup(hwaddr net.HardwareAddr) (lookupResult, error) {
	mac := hwaddr.String()
	now := p.now()
	if result, ok := p.cache.get(mac, now); ok {
		return result, nil
	}

	// The handler API has no context to inherit, and the client's own timeout
	// already bounds the request.
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

// INFORM carries no address request. RELEASE and DECLINE get no reply and free
// no state here, so looking them up would let a spoofed MAC turn every packet
// it sends into a NetBox API call.
func skipsLookup4(msgType dhcpv4.MessageType) bool {
	switch msgType {
	case dhcpv4.MessageTypeInform, dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// Handler4 handles DHCPv4 packets for the netbox plugin.
func (p *pluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if skipsLookup4(req.MessageType()) {
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

// Same reasoning as skipsLookup4.
func skipsLookup6(msgType dhcpv6.MessageType) bool {
	switch msgType {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// Handler6 handles DHCPv6 packets for the netbox plugin.
func (p *pluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	m, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("BUG: could not decapsulate: %v", err)
		return nil, true
	}

	// The relay wrapper's type is RELAY-FORW or RELAY-REPL and says nothing
	// about what the client sent, so the check runs on m, not req.
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
