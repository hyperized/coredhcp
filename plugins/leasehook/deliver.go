// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasehook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// signatureHeader carries the HMAC of the body when a secret is
	// configured.
	signatureHeader = "X-Coredhcp-Signature"

	// signaturePrefix names the digest, so a different one can be introduced
	// later without breaking a receiver that checks the prefix.
	signaturePrefix = "sha256="

	// contentType of the webhook body.
	contentType = "application/json"

	// maxResponseBytes bounds what is read from a webhook response. The body
	// is discarded either way; reading a little of it lets net/http reuse the
	// connection, and the limit stops a hostile endpoint from streaming into
	// a DHCP server.
	maxResponseBytes = 4 << 10

	// maxStderrBytes bounds how much of a failed program's stderr reaches the
	// log.
	maxStderrBytes = 1 << 10

	// envPrefix is put in front of every variable the exec target sets.
	envPrefix = "LEASEHOOK_"

	// localePrefix marks the LC_* locale overrides, passed through to a hook
	// program the same way the fixed allow list below is.
	localePrefix = "LC_"

	dialTimeout         = 2 * time.Second
	tlsHandshakeTimeout = 2 * time.Second
)

// allowedEnv is a short list rather than the whole environment because the
// server's own carries the secrets operators are told to pass as env:NAME:
// this plugin's secret, the ddns TSIG key, the redis password, the netbox API
// token. PATH is here so the program can find whatever it shells out to
// itself; the exec path leasehook runs has to be absolute either way.
var allowedEnv = []string{"PATH", "HOME", "TMPDIR", "LANG"}

// target delivers one event. deliver is called from the single worker
// goroutine and never concurrently with itself; ctx carries the configured
// per-delivery timeout.
type target interface {
	deliver(ctx context.Context, d delivery) error
}

type webhook struct {
	url    string
	secret []byte
	hc     *http.Client
}

// newWebhook returns a target posting to rawURL.
//
// The client gets no timeout of its own: the context the worker passes
// already bounds every delivery, and the per-phase timeouts below only keep a
// stuck TLS handshake from spending that whole budget on its own.
//
// CheckRedirect returns http.ErrUseLastResponse so a 3xx comes back as the
// response instead of the request, signature included, silently landing on
// whatever host the redirect pointed at.
//
// ForceAttemptHTTP2 has to be set explicitly, because giving the transport
// its own TLSClientConfig otherwise turns HTTP/2 off.
func newWebhook(rawURL string, secret []byte) *webhook {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxConnsPerHost:       2,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &webhook{url: rawURL, secret: secret, hc: client}
}

func (w *webhook) deliver(ctx context.Context, d delivery) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(d.payload))
	if err != nil {
		return fmt.Errorf("building the request for the webhook failed: %w; check the url: argument on the leasehook line", err)
	}
	req.Header.Set("Content-Type", contentType)
	if len(w.secret) > 0 {
		req.Header.Set(signatureHeader, sign(w.secret, d.payload))
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return fmt.Errorf("posting the event failed: %w; check the webhook host is reachable from this server and its certificate is valid", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("the endpoint answered %s; redirects are not followed, so point url: at the final URL and check it accepts a POST", resp.Status)
	}
	return nil
}

func sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	// hash.Hash documents that Write never returns an error.
	mac.Write(payload)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

type command struct {
	path string

	// extraEnv is never set in production: a hook program takes no arguments,
	// so a test that re-executes the test binary as the program has no other
	// way to tell it what to do.
	extraEnv []string
}

// deliver lets nothing from the packet reach a command line: the program is
// executed directly, with no arguments and no shell, so a hostname full of
// shell metacharacters is only ever data.
func (c *command) deliver(ctx context.Context, d delivery) error {
	// #nosec G204 -- the path comes from config.yml, is required to be
	// absolute, and no part of it is derived from a packet.
	cmd := exec.CommandContext(ctx, c.path)
	cmd.Stdin = bytes.NewReader(d.payload)
	cmd.Env = childEnv(append(d.env(), c.extraEnv...))
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s failed: %w%s; check the file exists and is executable by the user coredhcp runs as",
			c.path, err, stderrSuffix(stderr.Bytes()))
	}
	return nil
}

// childEnv invents nothing: a variable the parent does not have is left out
// rather than given a default.
func childEnv(extra []string) []string {
	env := make([]string, 0, len(allowedEnv)+len(extra))
	for _, name := range allowedEnv {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		env = append(env, name+"="+value)
	}
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, localePrefix) {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// env leaves delegated prefixes out; a script that needs those reads the body
// on stdin.
func (d delivery) env() []string {
	return []string{
		envPrefix + "EVENT=" + sanitizeEnv(d.ev.Event),
		envPrefix + "FAMILY=" + strconv.Itoa(d.ev.Family),
		envPrefix + "MAC=" + sanitizeEnv(d.ev.MAC),
		envPrefix + "ADDRESSES=" + sanitizeEnv(strings.Join(d.ev.Addresses, " ")),
		envPrefix + "HOSTNAME=" + sanitizeEnv(d.ev.Hostname),
	}
}

// sanitizeEnv guards the hostname, the one value that comes straight out of a
// packet: a NUL in it would stop os/exec from starting the program at all, and
// an escape sequence would be acted on by whatever reads the script's output.
func sanitizeEnv(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

func stderrSuffix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return ", stderr: " + truncateUTF8(strings.TrimSpace(string(b)), maxStderrBytes)
}
