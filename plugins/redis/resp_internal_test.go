// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package redis

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeServer speaks the four commands the client sends and lets a test override a reply to inject
// failures a healthy server would never produce.
type fakeServer struct {
	addr string
	ln   net.Listener
	// accepting and wg are separate so shutdown can wait for the accept loop to stop
	// before walking the connection list, avoiding a race on hangup.
	accepting sync.WaitGroup
	wg        sync.WaitGroup

	mu       sync.Mutex
	hashes   map[string]map[string]string
	commands [][]string
	conns    []net.Conn
	accepts  int
	respond  func(cmd []string, cn net.Conn) bool
}

// newFakeServer reaps the listener and every connection goroutine in cleanup, so a leak
// shows up as a hung test rather than as noise later.
func newFakeServer(t *testing.T, tlsConf *tls.Config) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}
	s := &fakeServer{addr: addr, ln: ln, hashes: make(map[string]map[string]string)}
	s.accepting.Add(1)
	go s.acceptLoop()
	t.Cleanup(func() {
		// The server has to hang up: a handler built through setup4 has no way to reach
		// the pooled connection its client is holding.
		_ = ln.Close()
		s.accepting.Wait()
		s.mu.Lock()
		for _, nc := range s.conns {
			_ = nc.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *fakeServer) acceptLoop() {
	defer s.accepting.Done()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepts++
		s.conns = append(s.conns, nc)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { _ = nc.Close() }()
			s.serve(nc)
		}()
	}
}

func (s *fakeServer) serve(nc net.Conn) {
	r := bufio.NewReader(nc)
	for {
		cmd, err := readCommand(r)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		respond := s.respond
		s.mu.Unlock()

		if respond != nil && respond(cmd, nc) {
			continue
		}
		if _, err := io.WriteString(nc, s.defaultReply(cmd)); err != nil {
			return
		}
	}
}

func (s *fakeServer) defaultReply(cmd []string) string {
	if len(cmd) == 0 {
		return "-ERR empty command\r\n"
	}
	switch strings.ToUpper(cmd[0]) {
	case "PING":
		return "+PONG\r\n"
	case "AUTH", "SELECT":
		return "+OK\r\n"
	case "HSET", "DEL":
		return ":1\r\n"
	case "HGETALL":
		return s.hashReply(cmd[1])
	default:
		return "-ERR unknown command\r\n"
	}
}

func (s *fakeServer) hashReply(key string) string {
	s.mu.Lock()
	fields := s.hashes[key]
	s.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", 2*len(fields))
	for name, value := range fields {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n$%d\r\n%s\r\n", len(name), name, len(value), value)
	}
	return b.String()
}

func (s *fakeServer) setHash(key string, fields map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashes[key] = fields
}

func (s *fakeServer) setRespond(fn func(cmd []string, cn net.Conn) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respond = fn
}

func (s *fakeServer) replyRaw(cmdName, raw string) {
	s.setRespond(func(cmd []string, cn net.Conn) bool {
		if !strings.EqualFold(cmd[0], cmdName) {
			return false
		}
		_, _ = io.WriteString(cn, raw)
		return true
	})
}

func (s *fakeServer) seen() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.commands...)
}

func (s *fakeServer) acceptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

// readCommand reads one RESP array of bulk strings, the only shape a client ever sends.
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := readTrimmed(r)
	if err != nil {
		return nil, err
	}
	argc, err := parseHeader(line, '*')
	if err != nil {
		return nil, err
	}
	cmd := make([]string, argc)
	for i := range cmd {
		if line, err = readTrimmed(r); err != nil {
			return nil, err
		}
		n, err := parseHeader(line, '$')
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		cmd[i] = string(buf[:n])
	}
	return cmd, nil
}

func parseHeader(line string, want byte) (int, error) {
	if len(line) < 2 || line[0] != want {
		return 0, fmt.Errorf("fake server: bad %q header %q", want, line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("fake server: bad %q length %q", want, line)
	}
	return n, nil
}

func readTrimmed(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// loopbackCert lets the rediss path be exercised without a fixture on disk or a switch to skip verification.
func loopbackCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "coredhcp redis test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func newTestClient(t *testing.T, s *fakeServer) *client {
	t.Helper()
	c := newClient(clientConfig{addr: s.addr, timeout: 5 * time.Second})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (c *client) idleCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.idle)
}

func TestRespReaderReplies(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		want     any
		wantErr  string
		protocol bool
	}{
		{name: "simple string", raw: "+PONG\r\n", want: "PONG"},
		{name: "integer", raw: ":42\r\n", want: int64(42)},
		{name: "negative integer", raw: ":-1\r\n", want: int64(-1)},
		{name: "bulk string", raw: "$5\r\nhello\r\n", want: "hello"},
		{name: "empty bulk string", raw: "$0\r\n\r\n", want: ""},
		{name: "nil bulk string", raw: "$-1\r\n", want: nil},
		{name: "array", raw: "*2\r\n$3\r\nfoo\r\n:7\r\n", want: []any{"foo", int64(7)}},
		{name: "empty array", raw: "*0\r\n", want: []any{}},
		{name: "nil array", raw: "*-1\r\n", want: nil},
		{
			name:    "error reply",
			raw:     "-ERR something broke\r\n",
			wantErr: "ERR something broke",
		},
		{
			name: "malformed integer", raw: ":twelve\r\n",
			wantErr: "malformed integer reply", protocol: true,
		},
		{
			name: "malformed bulk length", raw: "$x\r\n",
			wantErr: "malformed bulk length", protocol: true,
		},
		{
			name: "bulk length above the cap", raw: "$" + strconv.Itoa(maxBulkLen+1) + "\r\n",
			wantErr: "out of range", protocol: true,
		},
		{
			name: "bulk length below nil", raw: "$-2\r\n",
			wantErr: "out of range", protocol: true,
		},
		{
			name: "bulk string not terminated", raw: "$1\r\nabc\r\n",
			wantErr: "not terminated by CRLF", protocol: true,
		},
		{
			name: "bulk string cut short", raw: "$5\r\nhel",
			wantErr: "unexpected EOF",
		},
		{
			name: "malformed array length", raw: "*x\r\n",
			wantErr: "malformed array length", protocol: true,
		},
		{
			name: "array length above the cap", raw: "*" + strconv.Itoa(maxArrayLen+1) + "\r\n",
			wantErr: "out of range", protocol: true,
		},
		{
			name: "array length below nil", raw: "*-2\r\n",
			wantErr: "out of range", protocol: true,
		},
		{
			name: "nested array", raw: "*1\r\n*1\r\n$1\r\na\r\n",
			wantErr: "nested deeper", protocol: true,
		},
		{
			name: "array element fails to parse", raw: "*1\r\n$x\r\n",
			wantErr: "malformed bulk length", protocol: true,
		},
		{
			name: "unknown reply type", raw: "!nope\r\n",
			wantErr: "unknown reply type", protocol: true,
		},
		{
			name: "empty reply line", raw: "\r\n",
			wantErr: "empty reply line", protocol: true,
		},
		{
			name: "line without carriage return", raw: "+PONG\n",
			wantErr: "not terminated by CRLF", protocol: true,
		},
		{
			name: "bare newline", raw: "\n",
			wantErr: "not terminated by CRLF", protocol: true,
		},
		{
			name: "line longer than the buffer", raw: "+" + strings.Repeat("x", lineLimit) + "\r\n",
			wantErr: "longer than", protocol: true,
		},
		{name: "no reply at all", raw: "", wantErr: "EOF"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newRespReader(strings.NewReader(tc.raw)).readReply(0)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, got)
				assert.Equal(t, tc.protocol, errors.Is(err, errProtocol))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRespReaderErrorReplyType(t *testing.T) {
	_, err := newRespReader(strings.NewReader("-WRONGTYPE not a hash\r\n")).readReply(0)
	var rerr respError
	require.ErrorAs(t, err, &rerr)
	assert.Equal(t, "WRONGTYPE not a hash", string(rerr))
	assert.False(t, errors.Is(err, errProtocol))
}

// FuzzRespReader also checks that a failed parse never also yields a value the caller might act on.
func FuzzRespReader(f *testing.F) {
	for _, seed := range []string{
		"+OK\r\n", "-ERR x\r\n", ":1\r\n", "$3\r\nfoo\r\n", "$-1\r\n",
		"*2\r\n$1\r\na\r\n$1\r\nb\r\n", "*-1\r\n", "*1\r\n*0\r\n", "!\r\n", "",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := newRespReader(bytes.NewReader(data)).readReply(0)
		if err != nil && got != nil {
			t.Fatalf("got both a reply (%#v) and an error (%v)", got, err)
		}
	})
}

func TestClientCommands(t *testing.T) {
	s := newFakeServer(t, nil)
	c := newTestClient(t, s)

	require.NoError(t, c.ping())

	s.setHash("mac:aa:bb:cc:dd:ee:ff", map[string]string{"ipv4": "10.0.0.5/24", "router": "10.0.0.1"})
	fields, err := c.hgetall("mac:aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"ipv4": "10.0.0.5/24", "router": "10.0.0.1"}, fields)

	// An unknown key is an empty hash, not an error: that is what tells the handlers to pass the request on.
	fields, err = c.hgetall("mac:00:00:00:00:00:00")
	require.NoError(t, err)
	assert.Empty(t, fields)

	require.NoError(t, c.hset("mac:11:22:33:44:55:66", map[string]string{"ipv4": "10.0.0.6"}))
	require.NoError(t, c.del("mac:11:22:33:44:55:66"))

	assert.Equal(t, [][]string{
		{"PING"},
		{"HGETALL", "mac:aa:bb:cc:dd:ee:ff"},
		{"HGETALL", "mac:00:00:00:00:00:00"},
		{"HSET", "mac:11:22:33:44:55:66", "ipv4", "10.0.0.6"},
		{"DEL", "mac:11:22:33:44:55:66"},
	}, s.seen())
}

func TestClientHGETALLBadReplies(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"not an array", "+OK\r\n", "want an array"},
		{"odd element count", "*1\r\n$3\r\nfoo\r\n", "want an even number"},
		{"non-string element", "*2\r\n$3\r\nfoo\r\n:1\r\n", "non-string field or value"},
		{"error reply", "-WRONGTYPE not a hash\r\n", "WRONGTYPE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t, nil)
			c := newTestClient(t, s)
			s.replyRaw("HGETALL", tc.raw)

			fields, err := c.hgetall("mac:aa:bb:cc:dd:ee:ff")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Nil(t, fields)
		})
	}
}

func TestClientPoolReusesConnections(t *testing.T) {
	s := newFakeServer(t, nil)
	c := newTestClient(t, s)

	require.NoError(t, c.ping())
	require.NoError(t, c.ping())
	assert.Equal(t, 1, s.acceptCount(), "the second command should reuse the pooled connection")
	assert.Equal(t, 1, c.idleCount())
}

func TestClientRetiresConnectionAfterProtocolError(t *testing.T) {
	s := newFakeServer(t, nil)
	c := newTestClient(t, s)

	s.replyRaw("PING", "!garbage\r\n")
	require.Error(t, c.ping())
	assert.Zero(t, c.idleCount(), "a desynchronized connection must not go back to the pool")

	s.setRespond(nil)
	require.NoError(t, c.ping())
	assert.Equal(t, 2, s.acceptCount())
}

func TestClientKeepsConnectionAfterErrorReply(t *testing.T) {
	s := newFakeServer(t, nil)
	c := newTestClient(t, s)

	// An error reply leaves the stream in sync, so the connection is reused rather than redialed.
	s.replyRaw("PING", "-ERR nope\r\n")
	require.Error(t, c.ping())
	assert.Equal(t, 1, c.idleCount())

	require.Error(t, c.ping())
	assert.Equal(t, 1, s.acceptCount())
}

func TestClientAuthAndSelect(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
		db       int
		want     [][]string
	}{
		{
			name: "no credentials",
			want: [][]string{{"PING"}},
		},
		{
			name:     "password only",
			password: "hunter2",
			want:     [][]string{{"AUTH", "hunter2"}, {"PING"}},
		},
		{
			name:     "username and password",
			username: "coredhcp",
			password: "hunter2",
			want:     [][]string{{"AUTH", "coredhcp", "hunter2"}, {"PING"}},
		},
		{
			name: "database selected",
			db:   3,
			want: [][]string{{"SELECT", "3"}, {"PING"}},
		},
		{
			name:     "credentials and database",
			password: "hunter2",
			db:       1,
			want:     [][]string{{"AUTH", "hunter2"}, {"SELECT", "1"}, {"PING"}},
		},
		{
			name:     "username without a password sends no AUTH",
			username: "coredhcp",
			want:     [][]string{{"PING"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeServer(t, nil)
			c := newClient(clientConfig{
				addr:     s.addr,
				username: tc.username,
				password: tc.password,
				db:       tc.db,
				timeout:  5 * time.Second,
			})
			t.Cleanup(func() { _ = c.Close() })

			require.NoError(t, c.ping())
			assert.Equal(t, tc.want, s.seen())
		})
	}
}

func TestClientDialFailures(t *testing.T) {
	t.Run("nothing listening", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		c := newClient(clientConfig{addr: addr, timeout: time.Second})
		err = c.ping()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dialing redis at")
	})

	t.Run("AUTH rejected", func(t *testing.T) {
		s := newFakeServer(t, nil)
		s.replyRaw("AUTH", "-WRONGPASS invalid password\r\n")
		c := newClient(clientConfig{addr: s.addr, password: "hunter2", timeout: 5 * time.Second})
		t.Cleanup(func() { _ = c.Close() })

		err := c.ping()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authenticating to redis at")
		assert.NotContains(t, err.Error(), "hunter2")
	})

	t.Run("SELECT rejected", func(t *testing.T) {
		s := newFakeServer(t, nil)
		s.replyRaw("SELECT", "-ERR DB index is out of range\r\n")
		c := newClient(clientConfig{addr: s.addr, db: 99, timeout: 5 * time.Second})
		t.Cleanup(func() { _ = c.Close() })

		err := c.ping()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "selecting redis database 99")
	})
}

func TestClientTimeout(t *testing.T) {
	s := newFakeServer(t, nil)
	// Accept the command and say nothing: what a wedged server looks like from here.
	s.setRespond(func(_ []string, _ net.Conn) bool { return true })

	c := newClient(clientConfig{addr: s.addr, timeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })

	err := c.ping()
	require.Error(t, err)
	assert.True(t, os.IsTimeout(err), "want a timeout, got %v", err)
	assert.Zero(t, c.idleCount())
}

func TestClientClose(t *testing.T) {
	t.Run("closes idle connections and refuses commands", func(t *testing.T) {
		s := newFakeServer(t, nil)
		c := newTestClient(t, s)
		require.NoError(t, c.ping())
		require.Equal(t, 1, c.idleCount())

		require.NoError(t, c.Close())
		assert.Zero(t, c.idleCount())
		assert.ErrorIs(t, c.ping(), errClosed)
	})

	t.Run("a connection handed back after Close is not pooled", func(t *testing.T) {
		s := newFakeServer(t, nil)
		c := newTestClient(t, s)
		cn, err := c.get()
		require.NoError(t, err)

		require.NoError(t, c.Close())
		c.put(cn)
		assert.Zero(t, c.idleCount())
	})

	t.Run("reports the first failure", func(t *testing.T) {
		s := newFakeServer(t, nil)
		c := newTestClient(t, s)
		cn, err := c.get()
		require.NoError(t, err)
		c.put(cn)
		require.NoError(t, cn.close())

		assert.Error(t, c.Close())
	})
}

// TestClientPoolCap holds more commands in flight than the pool can keep, to
// check that the extra connections are closed instead of accumulating.
func TestClientPoolCap(t *testing.T) {
	const inFlight = maxIdleConns + 4

	s := newFakeServer(t, nil)
	c := newTestClient(t, s)

	var arrived sync.WaitGroup
	arrived.Add(inFlight)
	release := make(chan struct{})
	s.setRespond(func(cmd []string, _ net.Conn) bool {
		if cmd[0] != "HGETALL" {
			return false
		}
		arrived.Done()
		<-release
		return false
	})
	go func() {
		arrived.Wait()
		close(release)
	}()

	var wg sync.WaitGroup
	for range inFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.hgetall("mac:aa:bb:cc:dd:ee:ff")
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, inFlight, s.acceptCount())
	assert.Equal(t, maxIdleConns, c.idleCount())
}

type writeFailConn struct {
	net.Conn
	err error
}

func (c *writeFailConn) Write([]byte) (int, error)   { return 0, c.err }
func (c *writeFailConn) SetDeadline(time.Time) error { return nil }

func TestConnDoFailures(t *testing.T) {
	t.Run("deadline on a closed connection", func(t *testing.T) {
		s := newFakeServer(t, nil)
		c := newTestClient(t, s)
		cn, err := c.get()
		require.NoError(t, err)
		require.NoError(t, cn.close())

		_, err = cn.do(time.Second, "PING")
		assert.ErrorIs(t, err, net.ErrClosed)
	})

	t.Run("the write fails", func(t *testing.T) {
		// A kernel won't hand us a socket that takes a deadline and then refuses the write,
		// so the connection is stubbed instead.
		ours, theirs := net.Pipe()
		t.Cleanup(func() {
			_ = ours.Close()
			_ = theirs.Close()
		})
		nc := &writeFailConn{Conn: ours, err: errors.New("no room at the inn")}
		cn := &conn{nc: nc, rd: newRespReader(nc)}

		_, err := cn.do(time.Second, "PING")
		assert.ErrorIs(t, err, nc.err)
	})
}

func TestClientTLS(t *testing.T) {
	cert, pool := loopbackCert(t)
	s := newFakeServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	t.Run("trusted certificate", func(t *testing.T) {
		c := newClient(clientConfig{
			addr:    s.addr,
			tls:     &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12},
			timeout: 5 * time.Second,
		})
		t.Cleanup(func() { _ = c.Close() })
		require.NoError(t, c.ping())
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		c := newClient(clientConfig{
			addr:    s.addr,
			tls:     &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
			timeout: 5 * time.Second,
		})
		t.Cleanup(func() { _ = c.Close() })

		err := c.ping()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS handshake with")
	})

	t.Run("deadline on a closed connection", func(t *testing.T) {
		c := newClient(clientConfig{tls: &tls.Config{MinVersion: tls.VersionTLS12}, timeout: time.Second})
		ours, theirs := net.Pipe()
		require.NoError(t, ours.Close())
		require.NoError(t, theirs.Close())

		_, err := c.handshake(ours)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	})
}
