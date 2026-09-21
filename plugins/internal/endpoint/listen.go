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

// bindTimeout bounds the stale-socket probe rather than the bind, which is a
// syscall that returns at once: a connect to a listener whose accept backlog
// is full waits for room.
const bindTimeout = 5 * time.Second

// chmodFile is a seam: a chmod of a freshly created socket cannot be made to
// fail from a test, and the failure path matters.
var chmodFile = os.Chmod

// Listen binds the endpoint.
//
// A setup function has no context to inherit, so a caller passing
// context.Background still gets a bind that cannot hang the server's startup.
func (e Endpoint) Listen(ctx context.Context) (net.Listener, error) {
	ctx, cancel := context.WithTimeout(ctx, bindTimeout)
	defer cancel()

	if e.network == NetworkUnix {
		return e.listenUnix(ctx)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, NetworkTCP, e.address)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot listen on %s: %w; check what already holds the port with `ss -ltnp`, or give the plugin another port", e.plugin, e.Key(), err)
	}
	return ln, nil
}

// listenUnix leaves a window between the bind and the chmod in which the
// socket carries whatever the process umask left it. Closing that window means
// setting the umask globally, which races with everything else in the process,
// so the directory holding the socket is the thing to get right.
func (e Endpoint) listenUnix(ctx context.Context) (net.Listener, error) {
	if err := e.clearStaleSocket(ctx); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, NetworkUnix, e.address)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot listen on %s: %w; check that the directory exists and that the server's user may create a socket in it", e.plugin, e.Key(), err)
	}
	if err := chmodFile(e.address, e.mode); err != nil {
		// Serving on a socket with permissions nobody asked for is worse
		// than not serving: those permissions are the authentication.
		_ = ln.Close()
		return nil, fmt.Errorf("%s: cannot set mode %#o on %s: %w; check that the socket's directory belongs to the server's user", e.plugin, e.mode, e.address, err)
	}
	return ln, nil
}

// clearStaleSocket unlinks only a file that is a socket and that nothing
// answers on, so a second coredhcp with the same configuration fails to start
// instead of quietly stealing the first one's endpoint.
func (e Endpoint) clearStaleSocket(ctx context.Context) error {
	info, err := os.Stat(e.address)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: cannot inspect %s: %w; check the path, and the server's permissions on the directories leading to it", e.plugin, e.address, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s: %s exists and is not a socket, refusing to remove it; move that file aside, or give the plugin another path", e.plugin, e.address)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, NetworkUnix, e.address)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s: something is already listening on %s; stop the other coredhcp, or give this one another socket path", e.plugin, e.address)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The probe ran out of time rather than finding nobody home, so
		// whether the socket is stale is unknown.
		return fmt.Errorf("%s: cannot tell within %s whether %s is stale: %w; remove the socket by hand once nothing is listening on it", e.plugin, bindTimeout, e.address, ctxErr)
	}
	return os.Remove(e.address)
}
