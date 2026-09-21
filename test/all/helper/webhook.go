// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/coredhcp/coredhcp/test/all/internal/hookverify"
)

// maxWebhookBody bounds how much of a delivery body the helper reads. The
// leasehook plugin's own payloads are a few hundred bytes; anything past
// this is either a plugin bug or something else posting to this path.
const maxWebhookBody = 1 << 20

// bodyTextLimit is how much of an unparsable body gets recorded verbatim,
// enough to tell what went wrong without keeping arbitrary amounts of junk.
const bodyTextLimit = 256

// signatureHeader is the header the leasehook plugin signs its deliveries
// with.
const signatureHeader = "X-Coredhcp-Signature"

// webhookReceiver answers POST /hook for the leasehook plugin.
type webhookReceiver struct {
	secret string
	rec    *recorder
}

// handle reads one webhook delivery, checks its signature, and records it.
// It answers 204 whether or not the signature verifies, since the helper's
// job is to record what happened, not to police it.
func (h *webhookReceiver) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		http.Error(w, "reading the request body failed", http.StatusBadRequest)
		return
	}
	if len(body) > maxWebhookBody {
		http.Error(w, "request body exceeds the 1 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}

	signature := r.Header.Get(signatureHeader)
	rec := webhookRecord{
		When:           time.Now().UTC(),
		Signature:      signature,
		SignatureValid: hookverify.Verify(h.secret, signature, body),
		ContentType:    r.Header.Get("Content-Type"),
	}
	fillEvent(&rec, body)

	h.rec.addWebhook(rec)
	w.WriteHeader(http.StatusNoContent)
}

// fillEvent sets rec.Event to body when it parses as JSON, and otherwise
// records why it did not plus a truncated, human-readable copy of it.
func fillEvent(rec *webhookRecord, body []byte) {
	if json.Valid(body) {
		rec.Event = json.RawMessage(body)
		return
	}
	rec.BodyError = "request body is not valid JSON"
	rec.BodyText = truncate(body, bodyTextLimit)
}

// truncate returns body as a string, cut to at most n bytes.
func truncate(body []byte, n int) string {
	if len(body) > n {
		body = body[:n]
	}
	return string(body)
}
