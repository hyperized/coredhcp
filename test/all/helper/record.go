// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxRecords caps each in-memory slice. The compose test's rate-limit-burst
// case can send several thousand requests within a few seconds, and this
// process is meant to run for the length of the test suite; without a cap a
// long or noisy run would grow memory without bound instead of just serving
// the fixture.
const maxRecords = 20000

// netboxRecord is one call against the NetBox mock, authenticated or not.
type netboxRecord struct {
	When       time.Time `json:"when"`
	Path       string    `json:"path"`
	Query      string    `json:"query"`
	Scheme     string    `json:"scheme"`
	Authorized bool      `json:"authorized"`
	Status     int       `json:"status"`
}

// webhookRecord is one delivery received on the leasehook webhook endpoint.
type webhookRecord struct {
	When           time.Time       `json:"when"`
	Signature      string          `json:"signature"`
	SignatureValid bool            `json:"signature_valid"`
	ContentType    string          `json:"content_type"`
	Event          json.RawMessage `json:"event,omitempty"`
	BodyError      string          `json:"body_error,omitempty"`
	BodyText       string          `json:"body_text,omitempty"`
}

// recorder keeps every request the helper has seen: in memory for the
// /recorded/* endpoints, and on disk so a human reading a failed run has
// them too.
type recorder struct {
	mu      sync.Mutex
	dir     string
	netbox  []netboxRecord
	webhook []webhookRecord
}

// newRecorder returns a recorder that writes its files under dir.
func newRecorder(dir string) *recorder {
	return &recorder{dir: dir}
}

// addNetbox records a NetBox mock call.
func (r *recorder) addNetbox(rec netboxRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.netbox) < maxRecords {
		r.netbox = append(r.netbox, rec)
	}
	r.appendFile("netbox.jsonl", rec)
}

// addWebhook records a webhook delivery.
func (r *recorder) addWebhook(rec webhookRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.webhook) < maxRecords {
		r.webhook = append(r.webhook, rec)
	}
	r.appendFile("webhook.jsonl", rec)
}

// netboxRecords returns a copy of the recorded NetBox calls, in arrival order.
func (r *recorder) netboxRecords() []netboxRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]netboxRecord, len(r.netbox))
	copy(out, r.netbox)
	return out
}

// webhookRecords returns a copy of the recorded webhook deliveries, in
// arrival order.
func (r *recorder) webhookRecords() []webhookRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]webhookRecord, len(r.webhook))
	copy(out, r.webhook)
	return out
}

// appendFile writes one JSON line for rec to name under the results
// directory. The caller already holds r.mu, so concurrent callers cannot
// interleave lines. A failure here is logged and otherwise ignored: losing
// the on-disk copy of one record is not a reason to fail the HTTP request
// that produced it.
func (r *recorder) appendFile(name string, rec any) {
	line, err := json.Marshal(rec)
	if err != nil {
		slog.Error("marshaling a record for disk failed", "file", name, "error", err)
		return
	}
	line = append(line, '\n')

	f, err := os.OpenFile(filepath.Join(r.dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("opening the results file failed; check HELPER_RESULTS points at a writable directory", "file", name, "error", err)
		return
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(line); err != nil {
		slog.Error("writing the results file failed; check the volume behind HELPER_RESULTS has room", "file", name, "error", err)
	}
}
