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
	signatureHeader = "X-Coredhcp-Signature"

	// signaturePrefix names the digest, so a different one could be
	// introduced later without breaking a receiver that checks it.
	signaturePrefix = "sha256="

	contentType = "application/json"

	// maxResponseBytes bounds a drain, not a rejection: the body is
	// discarded either way, but a hostile endpoint should not stream forever.
	maxResponseBytes = 4 << 10

	maxStderrBytes = 1 << 10

	envPrefix = "LEASEHOOK_"
)

// Declared here so a test can drive the worker without a webhook or a
// program. deliver runs only on the single worker goroutine, never concurrently.
type target interface {
	deliver(ctx context.Context, d delivery) error
}

type webhook struct {
	url    string
	secret []byte
	hc     *http.Client
}

// No timeout on the client itself: every delivery is already bounded by the
// context the worker passes.
func newWebhook(rawURL string, secret []byte) *webhook {
	return &webhook{url: rawURL, secret: secret, hc: &http.Client{}}
}

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
	// Drained, not just closed, so net/http can reuse the connection.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("the endpoint answered %s", resp.Status)
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
}

// The program runs directly, with no arguments and no shell, so a hostname
// full of shell metacharacters is only ever data.
func (c *command) deliver(ctx context.Context, d delivery) error {
	// #nosec G204 -- path comes from config.yml, required absolute, never derived from a packet.
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

// Delegated prefixes are deliberately left out; a script that needs those
// reads the body on stdin.
func (d delivery) env() []string {
	return []string{
		envPrefix + "EVENT=" + sanitizeEnv(d.ev.Event),
		envPrefix + "FAMILY=" + strconv.Itoa(d.ev.Family),
		envPrefix + "MAC=" + sanitizeEnv(d.ev.MAC),
		envPrefix + "ADDRESSES=" + sanitizeEnv(strings.Join(d.ev.Addresses, " ")),
		envPrefix + "HOSTNAME=" + sanitizeEnv(d.ev.Hostname),
	}
}

// Only the hostname can carry control characters, straight from the packet:
// a NUL would stop the program starting, and other bytes could be misread.
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
