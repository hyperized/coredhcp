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
	// contentType is what every body this package writes is.
	contentType = "application/json; charset=utf-8"

	// familyParam and sourceParam are the only query parameters accepted, on
	// either collection endpoint.
	familyParam = "family"
	sourceParam = "source"

	// leasesField and poolsField name the array in each response. The
	// payload is an object rather than a bare array so that a later version
	// can add a field beside it without breaking a client.
	leasesField = "leases"
	poolsField  = "pools"
)

// The three errors a request can be rejected with. They are sentinels so a
// test can match them, and they describe the allow list instead of quoting
// what was asked for: an API that echoes its input back is one more place for
// something downstream to render it.
var (
	ErrUnknownParameter = errors.New("unknown query parameter, want family or source")
	ErrUnknownFamily    = errors.New("family must be 4 or 6")
	ErrUnknownSource    = errors.New("no such source")
)

// streamThreshold is how many entries a response may hold before it is written
// straight to the connection instead of being built in memory first.
//
// Under it, the body is encoded into a buffer, which keeps a failed encode
// from producing half a response. Over it, a server with a large pool would be
// holding tens of megabytes per concurrent request for no reason, so the
// entries go out one at a time. It is a var only so tests can lower it; the
// configuration cannot.
var streamThreshold = 100_000

// families is the allow list for the family parameter.
var families = map[string]uint8{"4": 4, "6": 6}

// filter is what a request asked to narrow the answer to. The zero filter
// matches everything.
type filter struct {
	// family is 4 or 6, or 0 for either.
	family uint8

	// source is the source name to match, and bySource says whether it was
	// given at all. A source name is never empty, so the two could be one
	// field; keeping them apart means a request for a source that does not
	// exist can be rejected rather than read as "any".
	source   string
	bySource bool
}

// matchesFamily reports whether a lease of this family is wanted.
func (f filter) matchesFamily(family uint8) bool {
	return f.family == 0 || f.family == family
}

// matchesSource reports whether a source of this name is wanted.
func (f filter) matchesSource(name string) bool {
	return !f.bySource || f.source == name
}

// parseFilter reads the query parameters.
//
// Both parameters are checked against an allow list, the source against the
// names actually registered, so nothing a client sends reaches the sources as
// anything but an equality test. Anything else is a 400: a mistyped filter
// that silently returned everything would be read as the truth about the
// network.
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

// registeredName reports whether any registered source goes by this name.
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

// servePools answers GET /v1/pools. It takes the same filters as the lease
// endpoint, since a reader showing one pool's utilisation wants the pool as
// well as its leases.
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
	// OK is always true: this endpoint answering at all is the health check.
	// It is there so a monitor can assert on the body rather than only on
	// the status code.
	OK bool `json:"ok"`

	// Sources is how many lease-holding plugin instances registered. Zero
	// means the API is up and has nothing to serve, which is a
	// configuration mistake rather than a failure.
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

// collectLeases gathers the leases matching f from every source.
//
// Every source is asked in turn and answers under its own lock, so this is a
// set of snapshots taken at slightly different moments rather than one
// consistent view of the whole server. Making it consistent would mean holding
// every plugin's lock at once, which would let an API request stall the packet
// path.
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

// collectPools gathers the pools matching f from every source.
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

// compareLeases orders leases by source, then by address.
//
// The order is total, down to the client, so that two requests answered from
// unchanged state return byte-identical bodies. Map iteration inside the
// sources is random, and a UI diffing two answers would otherwise see every
// lease move.
func compareLeases(a, b leases.Lease) int {
	return cmp.Or(
		strings.Compare(a.Source, b.Source),
		a.Address.Addr().Compare(b.Address.Addr()),
		cmp.Compare(a.Address.Bits(), b.Address.Bits()),
		strings.Compare(a.Client, b.Client),
	)
}

// comparePools orders pools by source, then by range.
func comparePools(a, b leases.Pool) int {
	return cmp.Or(
		strings.Compare(a.Source, b.Source),
		strings.Compare(a.Range, b.Range),
	)
}

// respond writes items as a JSON object holding one named array.
//
// A small answer is encoded into a buffer first, so that the connection sees
// either a whole body or none of it. A large one goes out entry by entry: see
// streamThreshold.
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

// encodeList writes {"<field>":[...]} with one entry per Encode call, so that
// the whole list is never held in memory in its encoded form.
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

// badRequest rejects a request, naming the allow list it failed rather than
// what it asked for. What it asked for goes to the debug log, where the
// operator can see it and a client cannot.
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

// setJSONHeaders declares the body type. Cache-Control is set for every
// response, this one included, by the noStore middleware.
func setJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentType)
}

// report logs a response that could not be written. There is nothing else to
// do with it: the status line is long gone, and a client hanging up mid-body
// is its own problem.
func report(err error) {
	if err != nil {
		log.Debugf("writing the response body: %v", err)
	}
}
