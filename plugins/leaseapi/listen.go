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
	networkUnix = "unix"
	networkTCP  = "tcp"

	modeArg = "mode"

	// Owner only: socket permissions are the whole authentication story
	// here, so the default has to be the closed one.
	defaultSocketMode os.FileMode = 0o600

	// Anything with a bit outside the permission bits is a typo, not an intent.
	maxSocketMode os.FileMode = 0o777

	addressSyntax = "unix:/path/to/socket or tcp:127.0.0.1:9755"
)

// A seam: a chmod of a socket just created cannot fail in any way a test can
// arrange, but the failure path matters — it closes the listener rather than
// serving one with permissions nobody asked for.
var chmodFile = os.Chmod

type endpoint struct {
	network string
	address string

	// Meaningless for a tcp endpoint.
	mode os.FileMode
}

func (e endpoint) key() string {
	return e.network + ":" + e.address
}

// Not a claim about the deployment: a socket in a world-writable directory,
// or a loopback port shared with every user on the host, is still reachable by them.
func (e endpoint) guard() string {
	if e.network == networkUnix {
		return fmt.Sprintf("socket mode %#o", e.mode)
	}
	return "loopback only"
}

// Not redundant with the bind that follows: these name the offending
// argument, where net.Listen's parse failure reads like a network problem,
// and the loopback check has no bind-time equivalent at all.
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

var endpointBuilders = map[string]func(address string, mode os.FileMode) (endpoint, error){
	networkUnix: unixEndpoint,
	networkTCP:  tcpEndpoint,
}

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

func unixEndpoint(address string, mode os.FileMode) (endpoint, error) {
	if address == "" {
		return endpoint{}, errors.New("leaseapi: unix socket path cannot be empty")
	}
	if mode == 0 {
		mode = defaultSocketMode
	}
	return endpoint{network: networkUnix, address: address, mode: mode}, nil
}

// A name that resolves to loopback is not accepted, only a literal address:
// this API is unauthenticated, and a resolver's answer can change behind the operator's back.
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

// There is a window between bind and chmod where the socket carries whatever
// the umask left it; that can't be closed without a global umask change, so
// the directory holding the socket is what has to be right instead.
func (e endpoint) listenUnix() (net.Listener, error) {
	if err := clearStaleSocket(e.address); err != nil {
		return nil, err
	}
	ln, err := net.Listen(networkUnix, e.address)
	if err != nil {
		return nil, fmt.Errorf("leaseapi: cannot listen on %s: %w", e.key(), err)
	}
	if err := chmodFile(e.address, e.mode); err != nil {
		// Those permissions are the authentication, so serving with the
		// wrong ones is worse than not serving.
		_ = ln.Close()
		return nil, fmt.Errorf("leaseapi: cannot set mode %#o on %s: %w", e.mode, e.address, err)
	}
	return ln, nil
}

// Only unlinks a path that is a socket and that nothing answers on, so a
// second coredhcp with the same configuration fails to start instead of
// quietly stealing the first one's API.
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
