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
	// lineLimit is the size of the read buffer, and with it the longest
	// single line the parser accepts. Only reply headers and simple strings
	// are read as lines; bulk payloads are read by length, so 4 KiB is
	// generous for everything this plugin sends.
	lineLimit = 4096

	// maxBulkLen and maxArrayLen bound a reply before any memory is
	// allocated for it. A hash of DHCP options is a few hundred bytes and a
	// handful of fields; these caps are orders of magnitude above that and
	// only exist so a broken or hostile server cannot make coredhcp allocate
	// on its behalf.
	maxBulkLen  = 1 << 20
	maxArrayLen = 4096

	// maxReplyDepth is how deep arrays may nest. The commands this plugin
	// sends (PING, AUTH, SELECT, HGETALL) reply with a scalar or one flat
	// array, so nested arrays are refused rather than walked.
	maxReplyDepth = 1

	// maxIdleConns caps the connection pool. A DHCP server handles one
	// packet per goroutine and each lookup is a single round trip, so the
	// pool exists to avoid a dial per packet, not to hold a large fleet of
	// sockets open.
	maxIdleConns = 8
)

// errProtocol wraps every reply this parser refuses to make sense of. It is
// deliberately distinct from respError: a protocol error means the stream is
// out of sync and the connection has to go, an error reply does not.
var errProtocol = errors.New("redis protocol error")

// errClosed is returned by a client whose Close has already run.
var errClosed = errors.New("redis client is closed")

// respError is an error reply from the server, the "-ERR ..." line. It is a
// well formed answer rather than a transport failure, so the connection
// stays in sync and goes back to the pool.
type respError string

// Error implements the error interface.
func (e respError) Error() string { return "redis replied: " + string(e) }

// protocolErrorf builds an error wrapping errProtocol, so callers can tell a
// desynchronized stream from a server side complaint with errors.Is.
func protocolErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errProtocol, fmt.Sprintf(format, args...))
}

// respReader parses RESP2 replies off a buffered stream. It is a separate
// type from conn so the parser can be tested and fuzzed without a socket.
type respReader struct {
	r *bufio.Reader
}

// newRespReader wraps r with the bounded buffer the parser reads lines from.
func newRespReader(r io.Reader) *respReader {
	return &respReader{r: bufio.NewReaderSize(r, lineLimit)}
}

// readLine returns the next line without its CRLF. The returned slice points
// into the read buffer and is only valid until the next read, so callers copy
// what they keep. A line longer than the buffer is refused instead of grown:
// nothing this plugin asks for has a long line, so an unterminated flood is a
// broken peer.
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

// readReply parses one reply. The concrete types it returns are: string for
// simple and bulk strings, int64 for integers, []any for arrays, and nil for
// both the nil bulk string and the nil array. An error reply comes back as a
// respError, not as a value.
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

// parseReplyInt decodes the payload of an integer reply.
func parseReplyInt(arg []byte) (any, error) {
	n, err := strconv.ParseInt(string(arg), 10, 64)
	if err != nil {
		return nil, protocolErrorf("malformed integer reply %q", arg)
	}
	return n, nil
}

// readBulk reads a bulk string whose declared length is arg. A length of -1
// is RESP2's nil and comes back as an untyped nil.
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
	// Read the payload and its CRLF in one go; a short stream fails here
	// rather than leaving a trailing terminator in the buffer.
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return nil, err
	}
	if buf[n] != '\r' || buf[n+1] != '\n' {
		return nil, protocolErrorf("bulk string not terminated by CRLF")
	}
	return string(buf[:n]), nil
}

// readArray reads an array of arg elements. A length of -1 is RESP2's nil
// array and comes back as an untyped nil.
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

// conn is one connection to the server: the socket, its parser, and the
// buffer commands are marshalled into. A conn is owned by a single goroutine
// for as long as it is out of the pool, so nothing here locks.
type conn struct {
	nc net.Conn
	rd *respReader
	w  bytes.Buffer
}

// close shuts the socket down.
func (cn *conn) close() error { return cn.nc.Close() }

// writeCommand marshals args as a RESP array of bulk strings and writes it in
// a single call. The buffer is kept on the conn and reused, so a steady stream
// of lookups does not allocate one per command.
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

// do sends one command and reads its reply, both under a single deadline. A
// server that accepts the connection and then goes quiet fails here instead
// of holding a DHCP goroutine forever.
func (cn *conn) do(timeout time.Duration, args ...string) (any, error) {
	if err := cn.nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := cn.writeCommand(args); err != nil {
		return nil, err
	}
	return cn.rd.readReply(0)
}

// clientConfig is everything needed to reach one Redis server. It is filled
// by the plugin's argument parser and read only afterwards.
type clientConfig struct {
	// addr is the host:port to dial.
	addr string
	// tls is non-nil for rediss:// and carries the ServerName to verify.
	tls *tls.Config
	// username and password feed AUTH. An empty password means no AUTH is
	// sent at all; a username without a password is ignored, as the two
	// argument form of AUTH requires both.
	username string
	password string
	// db is the database SELECTed on every fresh connection. Zero is the
	// default database and is left alone.
	db int
	// timeout bounds the dial, the TLS handshake, and each command.
	timeout time.Duration
}

// client is a small RESP2 client with a connection pool. It is safe for
// concurrent use: handlers run one goroutine per packet and share one client.
//
// The pool holds at most maxIdleConns connections. A connection that fails
// for any reason other than an error reply from the server is closed rather
// than reused, because a half written command or a half read reply leaves the
// stream out of sync.
type client struct {
	cfg clientConfig

	mu     sync.Mutex
	idle   []*conn
	closed bool
}

// newClient returns a client for cfg. Nothing is dialled here: the first
// command opens the first connection, which is what lets the plugin finish
// setup while the server is still down.
func newClient(cfg clientConfig) *client {
	return &client{cfg: cfg}
}

// Close closes every idle connection and refuses further commands.
// Connections that are checked out stay alive until their command finishes.
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

// get takes an idle connection or dials a new one.
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

// put returns a healthy connection to the pool, or closes it when the pool is
// full or the client has been closed.
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

// dial opens a connection and brings it up to the point where commands can be
// sent: TLS when configured, then AUTH and SELECT.
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

// handshake wraps nc in TLS under the dial timeout. On failure the underlying
// connection is closed, so a rejected certificate does not leak a socket.
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

// authenticate runs the per-connection setup commands. Errors name the server
// and the failing command but never the credentials.
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

// do runs one command on a pooled connection. An error reply keeps the
// connection, anything else retires it.
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

// ping checks that the server is reachable and, when credentials are
// configured, that they are accepted.
func (c *client) ping() error {
	_, err := c.do("PING")
	return err
}

// hgetall reads a whole hash. RESP2 answers with a flat array of alternating
// field names and values; a missing key is an empty array, which comes back
// as an empty map rather than an error.
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

// hset writes fields to a hash. Only the integration tests use it, to lay
// down their own fixtures through the same code path the handlers read
// through, rather than shelling out to redis-cli.
func (c *client) hset(key string, fields map[string]string) error {
	args := make([]string, 0, 2+2*len(fields))
	args = append(args, "HSET", key)
	for name, value := range fields {
		args = append(args, name, value)
	}
	_, err := c.do(args...)
	return err
}

// del removes keys, used by the integration tests to clean up after
// themselves.
func (c *client) del(keys ...string) error {
	_, err := c.do(append([]string{"DEL"}, keys...)...)
	return err
}
