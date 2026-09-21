// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The fixture interface every found MAC resolves to. The mock only ever
// serves one interface, so its id and names are fixed rather than
// configurable.
const (
	fixtureInterfaceID   = 42
	fixtureInterfaceName = "eth0"
	fixtureDeviceName    = "fixture-device"

	assignedObjectTypeInterface = "dcim.interface"

	msgUnauthorized = "authentication credentials were not provided or are invalid"
	msgMACNotFound  = "not found"
)

// netboxMock answers the two NetBox list endpoints the netbox plugin calls:
// the MAC address lookup and the IP address lookup that follows it.
type netboxMock struct {
	token       string
	mac         string
	macNotFound string
	addr4       string
	addr6       string
	rec         *recorder
}

// macAddresses answers GET /api/dcim/mac-addresses/.
func (n *netboxMock) macAddresses(w http.ResponseWriter, r *http.Request) {
	scheme, authorized := n.authorize(r)
	if !authorized {
		n.respond(w, r, scheme, false, http.StatusUnauthorized, detailBody(msgUnauthorized))
		return
	}

	mac := strings.ToLower(r.URL.Query().Get("mac_address"))
	switch {
	case mac == strings.ToLower(n.mac):
		n.respond(w, r, scheme, true, http.StatusOK, macFoundBody())
	case n.macNotFound != "" && mac == strings.ToLower(n.macNotFound):
		n.respond(w, r, scheme, true, http.StatusNotFound, detailBody(msgMACNotFound))
	default:
		// Real NetBox answers a filter that matches nothing with an empty
		// page, not a 404; the plugin reads that as "not documented" and
		// passes the request down its chain. A 404 here would make it treat
		// every undocumented MAC as a hard failure instead.
		n.respond(w, r, scheme, true, http.StatusOK, emptyResultsBody())
	}
}

// ipAddresses answers GET /api/ipam/ip-addresses/.
func (n *netboxMock) ipAddresses(w http.ResponseWriter, r *http.Request) {
	scheme, authorized := n.authorize(r)
	if !authorized {
		n.respond(w, r, scheme, false, http.StatusUnauthorized, detailBody(msgUnauthorized))
		return
	}

	if r.URL.Query().Get("interface_id") == strconv.Itoa(fixtureInterfaceID) {
		n.respond(w, r, scheme, true, http.StatusOK, ipResultsBody(n.addr4, n.addr6))
		return
	}
	n.respond(w, r, scheme, true, http.StatusOK, emptyResultsBody())
}

// authorize reports whether r carries a valid Authorization header for the
// mock, and which scheme it used. scheme is "Token" or "Bearer" when the
// header at least has a recognized prefix, and "" when it has neither.
func (n *netboxMock) authorize(r *http.Request) (scheme string, ok bool) {
	header := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(header, "Token "):
		return "Token", tokenMatches(n.token, strings.TrimPrefix(header, "Token "))
	case strings.HasPrefix(header, "Bearer "):
		return "Bearer", tokenMatches(n.token, strings.TrimPrefix(header, "Bearer "))
	default:
		return "", false
	}
}

// tokenMatches compares want and got in constant time, so a wrong token
// takes the same time to reject as an almost-right one.
func tokenMatches(want, got string) bool {
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// respond writes body as the JSON response and records the call.
func (n *netboxMock) respond(w http.ResponseWriter, r *http.Request, scheme string, authorized bool, status int, body any) {
	writeJSON(w, status, body)
	n.rec.addNetbox(netboxRecord{
		When:       time.Now().UTC(),
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Scheme:     scheme,
		Authorized: authorized,
		Status:     status,
	})
}

// macResultsPage is the shape of a /api/dcim/mac-addresses/ page carrying one
// match, matching the fields the netbox plugin reads and nothing else.
type macResultsPage struct {
	Results []macResult `json:"results"`
}

type macResult struct {
	AssignedObjectType string            `json:"assigned_object_type"`
	AssignedObjectID   int               `json:"assigned_object_id"`
	AssignedObject     macAssignedObject `json:"assigned_object"`
}

type macAssignedObject struct {
	Name   string          `json:"name"`
	Device macDeviceObject `json:"device"`
}

type macDeviceObject struct {
	Name string `json:"name"`
}

// macFoundBody is the response for the one MAC address the mock knows about.
func macFoundBody() macResultsPage {
	return macResultsPage{Results: []macResult{{
		AssignedObjectType: assignedObjectTypeInterface,
		AssignedObjectID:   fixtureInterfaceID,
		AssignedObject: macAssignedObject{
			Name:   fixtureInterfaceName,
			Device: macDeviceObject{Name: fixtureDeviceName},
		},
	}}}
}

// ipResultsPage is the shape of a /api/ipam/ip-addresses/ page.
type ipResultsPage struct {
	Results []ipResult `json:"results"`
}

type ipResult struct {
	Address string `json:"address"`
}

// ipResultsBody is the response for the fixture interface's addresses.
func ipResultsBody(addr4, addr6 string) ipResultsPage {
	return ipResultsPage{Results: []ipResult{{Address: addr4}, {Address: addr6}}}
}

// emptyResultsPage is the response NetBox gives for a filter matching
// nothing. The slice is built non-nil so it encodes as "[]", the way NetBox
// itself does, rather than as "null".
type emptyResultsPage struct {
	Results []struct{} `json:"results"`
}

func emptyResultsBody() emptyResultsPage {
	return emptyResultsPage{Results: []struct{}{}}
}

// detail is the small error body NetBox itself returns on 401 and 404.
type detail struct {
	Detail string `json:"detail"`
}

func detailBody(msg string) detail {
	return detail{Detail: msg}
}
