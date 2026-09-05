// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leaseapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// networkUnix and networkTCP are the two address schemes accepted, and
	// are the network names net.Listen takes as well.
	networkUnix = "unix"
	networkTCP  = "tcp"

	// modeArg names the optional argument setting the socket's permissions,
	// e.g. "mode:0660".
	modeArg = "mode"

	// defaultSocketMode is what a socket is chmod'ed to when the config does
	// not say. Owner only: the socket's permissions are the whole
	// authentication story here, so the default has to be the closed one.
	// mode:0660 with a group is the usual way to let an operator's tooling in.
	defaultSocketMode os.FileMode = 0o600

	// maxSocketMode is the widest mode accepted. Anything with a bit outside
	// the permission bits is a typo rather than an intent.
	maxSocketMode os.FileMode = 0o777

	// addressSyntax spells the address argument out for error messages.
	addressSyntax = "unix:/path/to/socket or tcp:127.0.0.1:9755"
)

// chmodFile is os.Chmod, extracted as a seam. A chmod of a socket that was
// just created cannot fail in any way a test can arrange, and the failure path
// matters: it closes the listener rather than serving on a socket with
// permissions nobody asked for.
var chmodFile = os.Chmod

// endpoint is a validated listen address.
type endpoint struct {
	// network is networkUnix or networkTCP, and address the socket path or
	// the host:port to bind.
	network string
	address string

	// mode is the permission the socket file is chmod'ed to, and is
	// meaningless for a tcp endpoint.
	mode os.FileMode
}

// key identifies the endpoint in the listener registry, and is what the logs
// and error messages call it.
func (e endpoint) key() string {
	return e.network + ":" + e.address
}

// guard names what keeps this endpoint from being world-readable, for the
// startup log. It is not a claim about the deployment: a socket in a
// world-writable directory or a loopback port shared with every user on the
// host is still reachable by whoever else is on that host.
func (e endpoint) guard() string {
	if e.network == networkUnix {
		return fmt.Sprintf("socket mode %#o", e.mode)
	}
	return "loopback only"
}

// parseArgs validates the plugin's arguments: an address, and for a unix
// socket an optional mode.
//
// The syntax checks are not redundant with the bind that follows. They name
// the offending argument, where net.Listen reports a parse failure that reads
// like a network problem, and the loopback check has no equivalent at bind
// time at all: binding a routable address succeeds.
func parseArgs(args []string) (endpoint, error) {
	if len(args) == 0 || len(args) > 2 {
		return endpoint{}, fmt.Errorf("leaseapi: expected one or two arguments, an address (%s) and an optional %s:<octal>, got %d",
			addressSyntax, modeArg, len(args))
	}
	network, address, ok := strings.Cut(strings.TrimSpace(args[0]), ":")
	if !ok {
		return endpoint{}, fmt.Errorf("leaseapi: invalid address %q, want %s", args[0], addressSyntax)
	}
	mode, err := parseMode(args[1:])
	if err != nil {
		return endpoint{}, err
	}
	build, known := endpointBuilders[network]
	if !known {
		return endpoint{}, fmt.Errorf("leaseapi: unknown address scheme %q, want %s", network, addressSyntax)
	}
	return build(address, mode)
}

// endpointBuilders dispatches on the address scheme. Each builder gets the
// part after the scheme and the mode, which is zero when the config gave none.
var endpointBuilders = map[string]func(address string, mode os.FileMode) (endpoint, error){
	networkUnix: unixEndpoint,
	networkTCP:  tcpEndpoint,
}

// parseMode reads the optional "mode:<octal>" argument, returning zero when it
// was not given.
func parseMode(extra []string) (os.FileMode, error) {
	if len(extra) == 0 {
		return 0, nil
	}
	key, value, ok := strings.Cut(strings.TrimSpace(extra[0]), ":")
	if !ok || key != modeArg {
		return 0, fmt.Errorf("leaseapi: unexpected argument %q, want %s:<octal>", extra[0], modeArg)
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("leaseapi: invalid %s %q, want an octal permission such as 0660: %w", modeArg, value, err)
	}
	mode := os.FileMode(parsed)
	if mode == 0 || mode > maxSocketMode {
		return 0, fmt.Errorf("leaseapi: %s %q is outside 0001-0777", modeArg, value)
	}
	return mode, nil
}

// unixEndpoint validates a "unix:<path>" address.
func unixEndpoint(address string, mode os.FileMode) (endpoint, error) {
	if address == "" {
		return endpoint{}, errors.New("leaseapi: unix socket path cannot be empty")
	}
	if mode == 0 {
		mode = defaultSocketMode
	}
	return endpoint{network: networkUnix, address: address, mode: mode}, nil
}

// tcpEndpoint validates a "tcp:<host>:<port>" address.
//
// The host has to be a loopback address, and a name that resolves to one will
// not do: this API is unauthenticated, and a name is resolved by whatever the
// host's resolver says today. 127.0.0.0/8 and ::1 are the only things that
// cannot become routable behind the operator's back.
func tcpEndpoint(address string, mode os.FileMode) (endpoint, error) {
	if mode != 0 {
		return endpoint{}, fmt.Errorf("leaseapi: %s applies to a unix socket, not to %s:%s", modeArg, networkTCP, address)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return endpoint{}, fmt.Errorf("leaseapi: invalid tcp address %q, want host:port: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return endpoint{}, fmt.Errorf("leaseapi: %q is not a loopback address: the lease API is unauthenticated and "+
			"publishes every client's address, so it listens on a unix socket or on 127.0.0.0/8 or ::1 only", host)
	}
	return endpoint{network: networkTCP, address: address}, nil
}

// listen binds the endpoint.
func (e endpoint) listen() (net.Listener, error) {
	if e.network == networkUnix {
		return e.listenUnix()
	}
	ln, err := net.Listen(networkTCP, e.address)
	if err != nil {
		return nil, fmt.Errorf("leaseapi: cannot listen on %s: %w", e.key(), err)
	}
	return ln, nil
}

// listenUnix binds a unix socket and sets its permissions.
//
// There is a window between the bind and the chmod in which the socket carries
// whatever the process umask left it. It cannot be closed from inside the
// process without setting the umask globally, which would race with everything
// else in it, so the directory holding the socket is the thing to get right:
// /run/coredhcp owned by the server's user is what the example configuration
// suggests.
func (e endpoint) listenUnix() (net.Listener, error) {
	if err := clearStaleSocket(e.address); err != nil {
		return nil, err
	}
	ln, err := net.Listen(networkUnix, e.address)
	if err != nil {
		return nil, fmt.Errorf("leaseapi: cannot listen on %s: %w", e.key(), err)
	}
	if err := chmodFile(e.address, e.mode); err != nil {
		// Serving on a socket with permissions nobody asked for is worse
		// than not serving: those permissions are the authentication.
		_ = ln.Close()
		return nil, fmt.Errorf("leaseapi: cannot set mode %#o on %s: %w", e.mode, e.address, err)
	}
	return ln, nil
}

// clearStaleSocket removes a socket file left behind by a previous run.
//
// A unix socket is a file, and a process that was killed rather than shut down
// leaves it there for the next bind to trip over. Removing it blindly would be
// worse than the problem: this only unlinks a file that is a socket and that
// nothing answers on, so a second coredhcp with the same configuration fails
// to start instead of quietly stealing the first one's API.
func clearStaleSocket(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("leaseapi: cannot inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("leaseapi: %s exists and is not a socket, refusing to remove it", path)
	}
	if conn, err := net.Dial(networkUnix, path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("leaseapi: something is already listening on %s", path)
	}
	return os.Remove(path)
}
