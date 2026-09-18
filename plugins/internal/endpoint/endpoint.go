// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package endpoint validates and binds the listen address of a plugin that
// serves HTTP alongside the DHCP server.
//
// Two plugins do that, leaseapi and metrics, and neither has any
// authentication to put in front of what it publishes: every client's MAC,
// DUID, hostname and address in the one case, how much traffic the server
// sees and of what kind in the other. The address it may bind is therefore
// the whole of the access control.
//
// An endpoint is a unix socket, whose file permissions decide who may read
// it, or a TCP port on 127.0.0.0/8 or ::1. There is deliberately no argument
// that unlocks a routable address. An operator who wants one of these
// reachable from another host puts a reverse proxy in front of it and
// authenticates there, or forwards the socket over ssh.
package endpoint

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// NetworkUnix is the scheme of a unix socket address, and the network
	// name a listener for one takes.
	NetworkUnix = "unix"

	// NetworkTCP is the scheme of a TCP address, and the network name a
	// listener for one takes.
	NetworkTCP = "tcp"

	// modeArg names the optional argument setting the socket's permissions,
	// e.g. "mode:0660".
	modeArg = "mode"

	// defaultSocketMode is owner only: the socket's permissions are the whole
	// authentication story here, so the default has to be the closed one.
	// mode:0660 with a group is the usual way to let an operator's tooling in.
	defaultSocketMode os.FileMode = 0o600

	// maxSocketMode is the widest mode accepted. Anything with a bit outside
	// the permission bits is a typo rather than an intent.
	maxSocketMode os.FileMode = 0o777
)

// Endpoint is a validated listen address.
//
// The zero Endpoint binds nothing; build one with Parse. It holds no state, so
// copying one and reading it from several goroutines is fine.
type Endpoint struct {
	// plugin prefixes every error, so a startup failure names the plugin whose
	// config.yml line it came from.
	plugin string

	network string
	address string

	// mode is meaningless for a tcp endpoint.
	mode os.FileMode
}

// Option changes how Parse reads its arguments.
type Option func(*parser)

type parser struct {
	plugin  string
	bareTCP bool
}

// AllowBareTCP reads an address with no scheme in front of it as a tcp
// address, so "127.0.0.1:9754" means what "tcp:127.0.0.1:9754" means.
//
// It is here for the metrics plugin, whose single argument has been a bare
// host:port for as long as the plugin has existed.
func AllowBareTCP() Option {
	return func(p *parser) { p.bareTCP = true }
}

// Parse validates a plugin's listen arguments: an address, and for a unix
// socket an optional mode:<octal>.
//
// The checks are not redundant with the bind that follows: they name the
// offending argument where a failed bind reads like a network problem, and
// the loopback check has no equivalent at bind time at all, since binding a
// routable address succeeds.
func Parse(plugin string, args []string, opts ...Option) (Endpoint, error) {
	p := &parser{plugin: plugin}
	for _, opt := range opts {
		opt(p)
	}
	if len(args) == 0 || len(args) > 2 {
		return Endpoint{}, fmt.Errorf("%s: expected one or two arguments, an address (%s) and an optional %s:<octal>, got %d",
			p.plugin, p.syntax(), modeArg, len(args))
	}
	mode, err := p.parseMode(args[1:])
	if err != nil {
		return Endpoint{}, err
	}
	return p.parseAddress(strings.TrimSpace(args[0]), mode)
}

func (p *parser) syntax() string {
	if p.bareTCP {
		return "unix:/path/to/socket, tcp:127.0.0.1:<port> or a bare 127.0.0.1:<port>"
	}
	return "unix:/path/to/socket or tcp:127.0.0.1:<port>"
}

func (p *parser) parseAddress(arg string, mode os.FileMode) (Endpoint, error) {
	network, address, ok := strings.Cut(arg, ":")
	if !ok {
		return Endpoint{}, fmt.Errorf("%s: invalid address %q, want %s", p.plugin, arg, p.syntax())
	}
	switch {
	case network == NetworkUnix:
		return p.unix(address, mode)
	case network == NetworkTCP:
		return p.tcp(address, mode)
	case p.bareTCP:
		// A hostname ends up here too and is rejected below for not being a
		// loopback literal, which is the error the operator needs either way.
		return p.tcp(arg, mode)
	default:
		return Endpoint{}, fmt.Errorf("%s: unknown address scheme %q, want %s", p.plugin, network, p.syntax())
	}
}

// parseMode returns zero when the mode argument was not given.
func (p *parser) parseMode(extra []string) (os.FileMode, error) {
	if len(extra) == 0 {
		return 0, nil
	}
	key, value, ok := strings.Cut(strings.TrimSpace(extra[0]), ":")
	if !ok || key != modeArg {
		return 0, fmt.Errorf("%s: unexpected argument %q, want %s:<octal>", p.plugin, extra[0], modeArg)
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid %s %q, want an octal permission such as 0660: %w", p.plugin, modeArg, value, err)
	}
	mode := os.FileMode(parsed)
	if mode == 0 || mode > maxSocketMode {
		return 0, fmt.Errorf("%s: %s %q is outside 0001-0777", p.plugin, modeArg, value)
	}
	return mode, nil
}

func (p *parser) unix(address string, mode os.FileMode) (Endpoint, error) {
	if address == "" {
		return Endpoint{}, fmt.Errorf("%s: unix socket path cannot be empty", p.plugin)
	}
	if mode == 0 {
		mode = defaultSocketMode
	}
	return Endpoint{plugin: p.plugin, network: NetworkUnix, address: address, mode: mode}, nil
}

// tcp refuses a name that resolves to loopback as well as one that does not:
// a name is resolved by whatever the host's resolver says today, and
// 127.0.0.0/8 and ::1 are the only things that cannot become routable behind
// the operator's back.
func (p *parser) tcp(address string, mode os.FileMode) (Endpoint, error) {
	if mode != 0 {
		return Endpoint{}, fmt.Errorf("%s: %s applies to a unix socket, not to %s:%s", p.plugin, modeArg, NetworkTCP, address)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%s: invalid tcp address %q, want host:port: %w", p.plugin, address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return Endpoint{}, fmt.Errorf("%s: %q is not a loopback address: this endpoint is unauthenticated and publishes "+
			"what the server knows, so it listens on a unix socket or on 127.0.0.0/8 or ::1 only, and anything wider "+
			"belongs behind a reverse proxy that authenticates", p.plugin, host)
	}
	return Endpoint{plugin: p.plugin, network: NetworkTCP, address: address}, nil
}

// Key identifies the endpoint in a plugin's listener registry, and is what the
// logs and the error messages call it.
func (e Endpoint) Key() string {
	return e.network + ":" + e.address
}

// Guard names what keeps this endpoint from being world-readable, for the
// startup log. It is not a claim about the deployment: a socket in a
// world-writable directory, or a loopback port on a shared host, is still
// reachable by more than the operator meant.
func (e Endpoint) Guard() string {
	if e.network == NetworkUnix {
		return fmt.Sprintf("socket mode %#o", e.mode)
	}
	return "loopback only"
}
