// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasehook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
)

// target delivers one event. The interface is declared here, where the worker
// consumes it, so a test can drive the worker without a webhook or a program.
//
// deliver is called from the single worker goroutine and never concurrently
// with itself. ctx carries the configured per-delivery timeout.
type target interface {
	deliver(ctx context.Context, d delivery) error
}

// webhook posts events to an HTTP endpoint.
type webhook struct {
	url    string
	secret []byte
	hc     *http.Client
}

// newWebhook returns a target posting to rawURL. The client is given no
// timeout of its own: every delivery is already bounded by the context the
// worker passes, and a second deadline would only be a second thing to keep
// in step with the configured one.
func newWebhook(rawURL string, secret []byte) *webhook {
	return &webhook{url: rawURL, secret: secret, hc: &http.Client{}}
}

// deliver posts one event and reads back enough of the answer to keep the
// connection reusable.
func (w *webhook) deliver(ctx context.Context, d delivery) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(d.payload))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if len(w.secret) > 0 {
		req.Header.Set(signatureHeader, sign(w.secret, d.payload))
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return fmt.Errorf("posting the event: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("the endpoint answered %s", resp.Status)
	}
	return nil
}

// sign returns the signature header value for one body.
func sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	// hash.Hash documents that Write never returns an error.
	mac.Write(payload)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// command runs a local program once per event.
type command struct {
	path string
}

// deliver runs the program with the JSON body on stdin and the event's main
// fields in the environment.
//
// Nothing from the packet reaches a command line: the program is executed
// directly, with no arguments and no shell, so a hostname full of shell
// metacharacters is only ever data.
func (c *command) deliver(ctx context.Context, d delivery) error {
	// #nosec G204 -- the path comes from config.yml, is required to be
	// absolute, and no part of it is derived from a packet.
	cmd := exec.CommandContext(ctx, c.path)
	cmd.Stdin = bytes.NewReader(d.payload)
	cmd.Env = append(os.Environ(), d.env()...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s: %w%s", c.path, err, stderrSuffix(stderr.Bytes()))
	}
	return nil
}

// env returns the LEASEHOOK_* variables for one event. Delegated prefixes are
// deliberately not among them; a script that needs those reads the body on
// stdin.
func (d delivery) env() []string {
	return []string{
		envPrefix + "EVENT=" + sanitizeEnv(d.ev.Event),
		envPrefix + "FAMILY=" + strconv.Itoa(d.ev.Family),
		envPrefix + "MAC=" + sanitizeEnv(d.ev.MAC),
		envPrefix + "ADDRESSES=" + sanitizeEnv(strings.Join(d.ev.Addresses, " ")),
		envPrefix + "HOSTNAME=" + sanitizeEnv(d.ev.Hostname),
	}
}

// sanitizeEnv replaces the control characters in a value with underscores.
// Only the hostname can carry any: it comes straight out of a packet, where a
// NUL would stop os/exec from starting the program at all and an escape
// sequence would be acted on by whatever reads the script's own output.
// Nothing else needs quoting, because a variable is not a command line.
func sanitizeEnv(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// stderrSuffix renders what a failed program wrote to stderr, or nothing when
// it wrote nothing.
func stderrSuffix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return ", stderr: " + truncateUTF8(strings.TrimSpace(string(b)), maxStderrBytes)
}
