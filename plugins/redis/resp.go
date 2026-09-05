// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	// Read buffer size, and with it the longest line the parser accepts. Only
	// headers and simple strings are lines; bulk payloads are read by length.
	lineLimit = 4096

	// Bound a reply before any memory is allocated for it, so a broken or
	// hostile server cannot make coredhcp allocate on its behalf.
	maxBulkLen  = 1 << 20
	maxArrayLen = 4096

	// PING, AUTH, SELECT and HGETALL reply with a scalar or one flat array, so
	// nested arrays are refused rather than walked.
	maxReplyDepth = 1

	// The pool exists to avoid a dial per packet, not to hold a fleet of
	// sockets open: each lookup is a single round trip.
	maxIdleConns = 8
)

// Distinct from respError: a protocol error means the stream is out of sync
// and the connection has to go, an error reply does not.
var errProtocol = errors.New("redis protocol error")

var errClosed = errors.New("redis client is closed")

// A well formed "-ERR ..." answer rather than a transport failure, so the
// connection stays in sync and goes back to the pool.
type respError string

func (e respError) Error() string { return "redis replied: " + string(e) }

// Wraps errProtocol so callers can tell a desynchronized stream from a server
// side complaint with errors.Is.
func protocolErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errProtocol, fmt.Sprintf(format, args...))
}

// Separate from conn so the parser can be tested and fuzzed without a socket.
type respReader struct {
	r *bufio.Reader
}

func newRespReader(r io.Reader) *respReader {
	return &respReader{r: bufio.NewReaderSize(r, lineLimit)}
}

// The slice points into the read buffer and is valid only until the next
// read. A line longer than the buffer is refused rather than grown.
func (p *respReader) readLine() ([]byte, error) {
	line, err := p.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, protocolErrorf("reply line longer than %d bytes", lineLimit)
	}
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, protocolErrorf("reply line not terminated by CRLF")
	}
	return line[:len(line)-2], nil
}

// Returns string for simple and bulk strings, int64 for integers, []any for
// arrays, nil for both nil forms, and a respError for an error reply.
func (p *respReader) readReply(depth int) (any, error) {
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, protocolErrorf("empty reply line")
	}
	switch line[0] {
	case '+':
		return string(line[1:]), nil
	case '-':
		return nil, respError(line[1:])
	case ':':
		return parseReplyInt(line[1:])
	case '$':
		return p.readBulk(line[1:])
	case '*':
		return p.readArray(line[1:], depth)
	default:
		return nil, protocolErrorf("unknown reply type %q", line[0])
	}
}

func parseReplyInt(arg []byte) (any, error) {
	n, err := strconv.ParseInt(string(arg), 10, 64)
	if err != nil {
		return nil, protocolErrorf("malformed integer reply %q", arg)
	}
	return n, nil
}

// A length of -1 is RESP2's nil and comes back as an untyped nil.
func (p *respReader) readBulk(arg []byte) (any, error) {
	n, err := strconv.Atoi(string(arg))
	if err != nil {
		return nil, protocolErrorf("malformed bulk length %q", arg)
	}
	if n == -1 {
		return nil, nil
	}
	if n < 0 || n > maxBulkLen {
		return nil, protocolErrorf("bulk length %d out of range", n)
	}
	// Payload and CRLF in one go: a short stream fails here rather than
	// leaving a trailing terminator in the buffer.
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return nil, err
	}
	if buf[n] != '\r' || buf[n+1] != '\n' {
		return nil, protocolErrorf("bulk string not terminated by CRLF")
	}
	return string(buf[:n]), nil
}

// A length of -1 is RESP2's nil array and comes back as an untyped nil.
func (p *respReader) readArray(arg []byte, depth int) (any, error) {
	n, err := strconv.Atoi(string(arg))
	if err != nil {
		return nil, protocolErrorf("malformed array length %q", arg)
	}
	if n == -1 {
		return nil, nil
	}
	if n < 0 || n > maxArrayLen {
		return nil, protocolErrorf("array length %d out of range", n)
	}
	if depth >= maxReplyDepth {
		return nil, protocolErrorf("array nested deeper than %d", maxReplyDepth)
	}
	out := make([]any, n)
	for i := range out {
		if out[i], err = p.readReply(depth + 1); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// A conn is owned by a single goroutine for as long as it is out of the pool,
// so nothing here locks.
type conn struct {
	nc net.Conn
	rd *respReader
	w  bytes.Buffer
}

func (cn *conn) close() error { return cn.nc.Close() }

// One write per command, out of a buffer kept on the conn, so a steady stream
// of lookups allocates nothing per command.
func (cn *conn) writeCommand(args []string) error {
	cn.w.Reset()
	cn.w.WriteByte('*')
	cn.w.WriteString(strconv.Itoa(len(args)))
	cn.w.WriteString("\r\n")
	for _, arg := range args {
		cn.w.WriteByte('$')
		cn.w.WriteString(strconv.Itoa(len(arg)))
		cn.w.WriteString("\r\n")
		cn.w.WriteString(arg)
		cn.w.WriteString("\r\n")
	}
	_, err := cn.nc.Write(cn.w.Bytes())
	return err
}

// One deadline covers both write and read, so a server that accepts the
// connection and then goes quiet cannot hold a DHCP goroutine forever.
func (cn *conn) do(timeout time.Duration, args ...string) (any, error) {
	if err := cn.nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := cn.writeCommand(args); err != nil {
		return nil, err
	}
	return cn.rd.readReply(0)
}

// Filled by the plugin's argument parser and read only afterwards.
type clientConfig struct {
	addr string
	// Non-nil for rediss://, carrying the ServerName to verify.
	tls *tls.Config
	// An empty password means no AUTH at all; a username without one is
	// ignored, since the two-argument AUTH requires both.
	username string
	password string
	// SELECTed on every fresh connection; zero is left alone.
	db int
	// Bounds the dial, the TLS handshake, and each command.
	timeout time.Duration
}

// Safe for concurrent use: handlers run one goroutine per packet and share one
// client. A connection that fails for anything but an error reply is closed
// rather than reused, because a half written command leaves the stream out of
// sync.
type client struct {
	cfg clientConfig

	mu     sync.Mutex
	idle   []*conn
	closed bool
}

// Nothing is dialled here, which is what lets the plugin finish setup while
// the server is still down.
func newClient(cfg clientConfig) *client {
	return &client{cfg: cfg}
}

// Close closes every idle connection and refuses further commands. Checked-out
// connections stay alive until their command finishes.
func (c *client) Close() error {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()

	var firstErr error
	for _, cn := range idle {
		if err := cn.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *client) get() (*conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if n := len(c.idle); n > 0 {
		cn := c.idle[n-1]
		c.idle[n-1] = nil
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return cn, nil
	}
	c.mu.Unlock()
	return c.dial()
}

func (c *client) put(cn *conn) {
	c.mu.Lock()
	if !c.closed && len(c.idle) < maxIdleConns {
		c.idle = append(c.idle, cn)
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	_ = cn.close()
}

func (c *client) dial() (*conn, error) {
	d := net.Dialer{Timeout: c.cfg.timeout}
	nc, err := d.Dial("tcp", c.cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("dialing redis at %s: %w", c.cfg.addr, err)
	}
	if c.cfg.tls != nil {
		if nc, err = c.handshake(nc); err != nil {
			return nil, err
		}
	}
	cn := &conn{nc: nc, rd: newRespReader(nc)}
	if err := c.authenticate(cn); err != nil {
		_ = cn.close()
		return nil, err
	}
	return cn, nil
}

// On failure the underlying connection is closed, so a rejected certificate
// does not leak a socket.
func (c *client) handshake(nc net.Conn) (net.Conn, error) {
	if err := nc.SetDeadline(time.Now().Add(c.cfg.timeout)); err != nil {
		_ = nc.Close()
		return nil, err
	}
	tc := tls.Client(nc, c.cfg.tls)
	if err := tc.Handshake(); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", c.cfg.addr, err)
	}
	return tc, nil
}

// Errors name the server and the failing command, never the credentials.
func (c *client) authenticate(cn *conn) error {
	if c.cfg.password != "" {
		args := []string{"AUTH", c.cfg.password}
		if c.cfg.username != "" {
			args = []string{"AUTH", c.cfg.username, c.cfg.password}
		}
		if _, err := cn.do(c.cfg.timeout, args...); err != nil {
			return fmt.Errorf("authenticating to redis at %s: %w", c.cfg.addr, err)
		}
	}
	if c.cfg.db != 0 {
		if _, err := cn.do(c.cfg.timeout, "SELECT", strconv.Itoa(c.cfg.db)); err != nil {
			return fmt.Errorf("selecting redis database %d at %s: %w", c.cfg.db, c.cfg.addr, err)
		}
	}
	return nil
}

// An error reply keeps the connection, anything else retires it.
func (c *client) do(args ...string) (any, error) {
	cn, err := c.get()
	if err != nil {
		return nil, err
	}
	reply, err := cn.do(c.cfg.timeout, args...)
	var rerr respError
	if err != nil && !errors.As(err, &rerr) {
		_ = cn.close()
		return nil, err
	}
	c.put(cn)
	return reply, err
}

func (c *client) ping() error {
	_, err := c.do("PING")
	return err
}

// RESP2 answers with a flat array of alternating names and values; a missing
// key is an empty array, and comes back as an empty map rather than an error.
func (c *client) hgetall(key string) (map[string]string, error) {
	reply, err := c.do("HGETALL", key)
	if err != nil {
		return nil, err
	}
	arr, ok := reply.([]any)
	if !ok {
		return nil, protocolErrorf("HGETALL replied with %T, want an array", reply)
	}
	if len(arr)%2 != 0 {
		return nil, protocolErrorf("HGETALL replied with %d elements, want an even number", len(arr))
	}
	out := make(map[string]string, len(arr)/2)
	for i := 0; i < len(arr); i += 2 {
		name, nameOK := arr[i].(string)
		value, valueOK := arr[i+1].(string)
		if !nameOK || !valueOK {
			return nil, protocolErrorf("HGETALL replied with a non-string field or value")
		}
		out[name] = value
	}
	return out, nil
}

// Only the integration tests use this, so their fixtures go down through the
// same code path the handlers read through.
func (c *client) hset(key string, fields map[string]string) error {
	args := make([]string, 0, 2+2*len(fields))
	args = append(args, "HSET", key)
	for name, value := range fields {
		args = append(args, name, value)
	}
	_, err := c.do(args...)
	return err
}

// Only the integration tests use this, to clean up after themselves.
func (c *client) del(keys ...string) error {
	_, err := c.do(append([]string{"DEL"}, keys...)...)
	return err
}
