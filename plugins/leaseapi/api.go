// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leaseapi

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/coredhcp/coredhcp/leases"
)

const (
	contentType = "application/json; charset=utf-8"

	// The only query parameters accepted, on either collection endpoint.
	familyParam = "family"
	sourceParam = "source"

	// The payload is an object rather than a bare array so a later version
	// can add a field beside it without breaking a client.
	leasesField = "leases"
	poolsField  = "pools"
)

// Sentinels so a test can match them. They describe the allow list instead
// of quoting what was asked for, so a client's input never gets echoed back.
var (
	ErrUnknownParameter = errors.New("unknown query parameter, want family or source")
	ErrUnknownFamily    = errors.New("family must be 4 or 6")
	ErrUnknownSource    = errors.New("no such source")
)

// A var, not a const, only so tests can lower it; the configuration cannot.
var streamThreshold = 100_000

var families = map[string]uint8{"4": 4, "6": 6}

// The zero filter matches everything.
type filter struct {
	// 4, 6, or 0 for either.
	family uint8

	// Kept apart from an empty source, which is never valid, so a
	// nonexistent source is rejected rather than read as "any".
	source   string
	bySource bool
}

func (f filter) matchesFamily(family uint8) bool {
	return f.family == 0 || f.family == family
}

func (f filter) matchesSource(name string) bool {
	return !f.bySource || f.source == name
}

// Both parameters are checked against an allow list, source against the
// names actually registered, so nothing a client sends reaches a source as
// more than an equality test — a mistyped filter must 400, not silently return everything.
func parseFilter(q url.Values) (filter, error) {
	for key := range q {
		if key != familyParam && key != sourceParam {
			return filter{}, ErrUnknownParameter
		}
	}
	var f filter
	if q.Has(familyParam) {
		family, ok := families[q.Get(familyParam)]
		if !ok {
			return filter{}, ErrUnknownFamily
		}
		f.family = family
	}
	if q.Has(sourceParam) {
		name := q.Get(sourceParam)
		if !registeredName(name) {
			return filter{}, ErrUnknownSource
		}
		f.source, f.bySource = name, true
	}
	return f, nil
}

func registeredName(name string) bool {
	for _, s := range leases.Sources() {
		if s.Name() == name {
			return true
		}
	}
	return false
}

// serveLeases answers GET /v1/leases.
func serveLeases(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r.URL.Query())
	if err != nil {
		badRequest(w, r, err)
		return
	}
	respond(w, leasesField, collectLeases(f))
}

// servePools answers GET /v1/pools, with the same filters as /v1/leases: a
// reader showing one pool's utilisation wants the pool and its leases both.
func servePools(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r.URL.Query())
	if err != nil {
		badRequest(w, r, err)
		return
	}
	respond(w, poolsField, collectPools(f))
}

// health is the body of GET /v1/health.
type health struct {
	// Always true: answering at all is the health check. Present so a
	// monitor can assert on the body, not just the status code.
	OK bool `json:"ok"`

	// Lease-holding plugin instances registered. Zero means the API is up
	// with nothing to serve — a configuration mistake, not a failure.
	Sources int `json:"sources"`
}

// serveHealth answers GET /v1/health.
func serveHealth(w http.ResponseWriter, _ *http.Request) {
	var buf bytes.Buffer
	// Encoding two scalars into a bytes.Buffer has nothing to fail on.
	_ = json.NewEncoder(&buf).Encode(health{OK: true, Sources: len(leases.Sources())})
	setJSONHeaders(w)
	_, err := w.Write(buf.Bytes())
	report(err)
}

// Each source answers under its own lock: a set of snapshots from slightly
// different moments, not one view — that would mean holding every lock at once.
func collectLeases(f filter) []leases.Lease {
	var out []leases.Lease
	for _, s := range leases.Sources() {
		if !f.matchesSource(s.Name()) {
			continue
		}
		for _, l := range s.Leases() {
			if f.matchesFamily(l.Family) {
				out = append(out, l)
			}
		}
	}
	slices.SortFunc(out, compareLeases)
	return out
}

func collectPools(f filter) []leases.Pool {
	var out []leases.Pool
	for _, s := range leases.Sources() {
		if !f.matchesSource(s.Name()) {
			continue
		}
		for _, p := range s.Pools() {
			if f.matchesFamily(p.Family) {
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, comparePools)
	return out
}

// Total down to the client, so two requests against unchanged state return
// byte-identical bodies despite each source's map iteration being random.
func compareLeases(a, b leases.Lease) int {
	return cmp.Or(
		strings.Compare(a.Source, b.Source),
		a.Address.Addr().Compare(b.Address.Addr()),
		cmp.Compare(a.Address.Bits(), b.Address.Bits()),
		strings.Compare(a.Client, b.Client),
	)
}

func comparePools(a, b leases.Pool) int {
	return cmp.Or(
		strings.Compare(a.Source, b.Source),
		strings.Compare(a.Range, b.Range),
	)
}

// Below streamThreshold, encoded into a buffer first so the connection sees
// a whole body or none of it; above it, entries go out one at a time.
func respond[T any](w http.ResponseWriter, field string, items []T) {
	setJSONHeaders(w)
	if len(items) > streamThreshold {
		report(encodeList(w, field, items))
		return
	}
	var buf bytes.Buffer
	// A bytes.Buffer never fails a write, and neither Lease nor Pool has a
	// field encoding/json can refuse.
	_ = encodeList(&buf, field, items)
	_, err := w.Write(buf.Bytes())
	report(err)
}

// Writes {"<field>":[...]} with one Encode call per entry, so the list is
// never held in memory in its encoded form.
func encodeList[T any](w io.Writer, field string, items []T) error {
	if _, err := fmt.Fprintf(w, "{%q:[", field); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for i := range items {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		// Encode appends a newline, which is whitespace between two array
		// entries and costs one byte to leave in.
		if err := enc.Encode(items[i]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]}")
	return err
}

// apiError is the body of a rejected request.
type apiError struct {
	Error string `json:"error"`
}

// Names the allow list a request failed, not what it asked for; what it
// asked for goes only to the debug log, which a client cannot read.
func badRequest(w http.ResponseWriter, r *http.Request, err error) {
	// RequestURI is the raw, still percent-encoded form, so nothing a client
	// sends can put a newline in a log line.
	log.Debugf("rejecting %s from %s: %v", r.URL.RequestURI(), r.RemoteAddr, err)

	var buf bytes.Buffer
	// One string into a bytes.Buffer: nothing to fail on.
	_ = json.NewEncoder(&buf).Encode(apiError{Error: err.Error()})
	setJSONHeaders(w)
	w.WriteHeader(http.StatusBadRequest)
	_, werr := w.Write(buf.Bytes())
	report(werr)
}

// Cache-Control is set separately, for every response, by the noStore middleware.
func setJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentType)
}

// Nothing else to do with a write failure here: the status line is long
// gone, and a client hanging up mid-body is its own problem.
func report(err error) {
	if err != nil {
		log.Debugf("writing the response body: %v", err)
	}
}
