// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
)

// bindTimeout bounds the work Listen does.
//
// It is not about the bind, which is a syscall that returns at once. It is
// the stale-socket probe: clearing a socket file a killed process left behind
// means connecting to whatever might still be answering on it, and a connect
// to a listener whose accept backlog is full waits for room.
const bindTimeout = 5 * time.Second

// chmodFile is os.Chmod, extracted as a seam. A chmod of a socket that was
// just created cannot fail in any way a test can arrange, and the failure path
// matters: it closes the listener rather than serving on a socket with
// permissions nobody asked for.
var chmodFile = os.Chmod

// Listen binds the endpoint.
//
// ctx is the caller's, with a deadline of Listen's own on top of it. Plugin
// setup has no context to inherit, since a setup function takes its arguments
// and nothing else, so the caller passes context.Background and still gets a
// bind that cannot hang the server's startup.
func (e Endpoint) Listen(ctx context.Context) (net.Listener, error) {
	ctx, cancel := context.WithTimeout(ctx, bindTimeout)
	defer cancel()

	if e.network == NetworkUnix {
		return e.listenUnix(ctx)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, NetworkTCP, e.address)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot listen on %s: %w", e.plugin, e.Key(), err)
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
func (e Endpoint) listenUnix(ctx context.Context) (net.Listener, error) {
	if err := e.clearStaleSocket(ctx); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, NetworkUnix, e.address)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot listen on %s: %w", e.plugin, e.Key(), err)
	}
	if err := chmodFile(e.address, e.mode); err != nil {
		// Serving on a socket with permissions nobody asked for is worse
		// than not serving: those permissions are the authentication.
		_ = ln.Close()
		return nil, fmt.Errorf("%s: cannot set mode %#o on %s: %w", e.plugin, e.mode, e.address, err)
	}
	return ln, nil
}

// clearStaleSocket removes a socket file left behind by a previous run.
//
// A unix socket is a file, and a process that was killed rather than shut down
// leaves it there for the next bind to trip over. Removing it blindly would be
// worse than the problem: this only unlinks a file that is a socket and that
// nothing answers on, so a second coredhcp with the same configuration fails
// to start instead of quietly stealing the first one's endpoint.
func (e Endpoint) clearStaleSocket(ctx context.Context) error {
	info, err := os.Stat(e.address)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: cannot inspect %s: %w", e.plugin, e.address, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s: %s exists and is not a socket, refusing to remove it", e.plugin, e.address)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, NetworkUnix, e.address)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s: something is already listening on %s", e.plugin, e.address)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The probe ran out of time rather than finding nobody home, so
		// whether the socket is stale is unknown. Unlinking it on that would
		// be the one thing this function exists to avoid.
		return fmt.Errorf("%s: cannot tell whether %s is stale: %w", e.plugin, e.address, ctxErr)
	}
	return os.Remove(e.address)
}
