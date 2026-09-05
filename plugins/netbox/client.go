// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// macAddressPath lists MAC address objects. NetBox 4.2 promoted MAC
	// addresses to a model of their own; before that they were a field on the
	// interface and this endpoint does not exist.
	macAddressPath = "/api/dcim/mac-addresses/"
	// ipAddressPath lists IP address objects, filtered by the interface they
	// are assigned to.
	ipAddressPath = "/api/ipam/ip-addresses/"

	// macAddressLimit caps the MAC query. A MAC should be unique in NetBox;
	// asking for a few more makes a duplicated or unassigned entry visible
	// instead of hiding the assigned one behind it.
	macAddressLimit = 10
	// ipAddressLimit caps the address query. We only need the first address
	// of each family, but an interface may legitimately carry several and the
	// order NetBox returns them in is the operator's.
	ipAddressLimit = 20

	// assigned_object_type values we can serve addresses for.
	objectTypeInterface   = "dcim.interface"
	objectTypeVMInterface = "virtualization.vminterface"

	// The query parameter naming each object type on the IP address endpoint.
	paramInterfaceID   = "interface_id"
	paramVMInterfaceID = "vminterface_id"

	// tokenPrefix marks a token argument as a secret. The config loader
	// redacts an argument's logged value when it starts with "token:",
	// "password:" or "secret:"; a bare argument gets no such treatment and
	// is printed in full.
	tokenPrefix = "token:"
	// tokenEnvPrefix marks a token argument that names an environment
	// variable instead of carrying the secret in config.yml.
	tokenEnvPrefix = "env:"
	// tokenV2Prefix identifies a NetBox 4.5 style token, which authenticates
	// as a bearer token. Older tokens use the "Token" scheme.
	tokenV2Prefix = "nbt_"

	// maxBodyBytes bounds a response body. The two list responses we ask for
	// are a few kilobytes at most; anything past this is either a NetBox bug
	// or something else answering on that URL, and reading it into memory on
	// a DHCP server is not worth it.
	maxBodyBytes = 1 << 20
)

// client talks to one NetBox instance.
//
// It is safe for concurrent use: every field is set at construction and read
// only afterwards, and http.Client is itself concurrency-safe.
type client struct {
	base string // no trailing slash, e.g. "https://netbox.example.com"
	auth string // full Authorization header value
	hc   *http.Client
}

// newClient returns a client for baseURL. baseURL must already be normalized
// by parseBaseURL and token resolved by resolveToken.
func newClient(baseURL, token string, timeout time.Duration) *client {
	return &client{
		base: baseURL,
		auth: authHeader(token),
		hc:   &http.Client{Timeout: timeout},
	}
}

// parseBaseURL validates the configured NetBox URL and returns it without a
// trailing slash, so paths can be appended directly. A subpath is allowed:
// NetBox is often mounted somewhere other than the root of its host.
func parseBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid NetBox URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid NetBox URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid NetBox URL %q: missing host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid NetBox URL %q: must not carry a query or fragment", raw)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// resolveToken returns the API token to authenticate with. The accepted
// forms are token:env:NAME and token:<value>, which name the argument as a
// secret so the config loader's redaction rule (a "token:", "password:" or
// "secret:" prefix) finds it, plus the older bare env:NAME and a bare
// literal for compatibility. token:env:NAME is the recommended form.
//
// A bare literal is still accepted, since rejecting it would break existing
// configs, but the config loader cannot tell it apart from a non-secret
// argument and logs it in full at startup, so this is warned about once at
// setup rather than silently allowed.
func resolveToken(arg string) (string, error) {
	if arg == "" {
		return "", errors.New("API token cannot be empty")
	}
	if rest, ok := strings.CutPrefix(arg, tokenPrefix); ok {
		return resolveTaggedToken(arg, rest)
	}
	if name, ok := strings.CutPrefix(arg, tokenEnvPrefix); ok {
		return resolveEnvToken(arg, name)
	}
	log.Warning("the API token is given as a bare argument, which the config loader cannot tell is a secret and logs in full at startup; give it as token:env:NAME instead")
	return arg, nil
}

// resolveTaggedToken handles a "token:"-prefixed argument, dispatching to
// resolveEnvToken for its env: form and treating anything else as a literal
// token value. arg is the original argument, kept for error messages.
func resolveTaggedToken(arg, rest string) (string, error) {
	if name, ok := strings.CutPrefix(rest, tokenEnvPrefix); ok {
		return resolveEnvToken(arg, name)
	}
	if rest == "" {
		return "", fmt.Errorf("token argument %q needs a token or %sNAME after %q", arg, tokenEnvPrefix, tokenPrefix)
	}
	return rest, nil
}

// resolveEnvToken reads the token from the environment variable named name,
// which comes from an "env:NAME" or "token:env:NAME" argument. arg is the
// original argument, kept for error messages.
func resolveEnvToken(arg, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("token argument %q needs an environment variable name after %q", arg, tokenEnvPrefix)
	}
	token := os.Getenv(name)
	if token == "" {
		return "", fmt.Errorf("environment variable %s is unset or empty", name)
	}
	return token, nil
}

// authHeader picks the authentication scheme for token. NetBox 4.5 introduced
// v2 tokens, which are bearer tokens and carry an "nbt_" prefix; every older
// token uses NetBox' own "Token" scheme.
func authHeader(token string) string {
	if strings.HasPrefix(token, tokenV2Prefix) {
		return "Bearer " + token
	}
	return "Token " + token
}

// interfaceRef points at the interface a MAC address is assigned to, on either
// a device or a virtual machine.
type interfaceRef struct {
	param  string // query parameter naming this kind of interface
	id     int64
	name   string
	parent string // device or virtual machine name, for log lines
}

// String renders the interface the way an operator would name it.
func (r interfaceRef) String() string {
	return r.name + " on " + r.parent
}

// macAddressPage is the part of a /api/dcim/mac-addresses/ list response we
// read. Everything else NetBox returns is deliberately ignored.
type macAddressPage struct {
	Results []macAddress `json:"results"`
}

type macAddress struct {
	AssignedObjectType string          `json:"assigned_object_type"`
	AssignedObjectID   int64           `json:"assigned_object_id"`
	AssignedObject     *assignedObject `json:"assigned_object"`
}

type assignedObject struct {
	Name           string       `json:"name"`
	Device         *namedObject `json:"device"`
	VirtualMachine *namedObject `json:"virtual_machine"`
}

type namedObject struct {
	Name string `json:"name"`
}

// interfaceRef returns the interface this MAC address is assigned to, or nil
// when it is unassigned or attached to something we cannot serve addresses
// for (a FHRP group, say).
func (m *macAddress) interfaceRef() *interfaceRef {
	if m.AssignedObject == nil || m.AssignedObjectID == 0 {
		return nil
	}
	switch m.AssignedObjectType {
	case objectTypeInterface:
		return m.AssignedObject.ref(paramInterfaceID, m.AssignedObjectID)
	case objectTypeVMInterface:
		return m.AssignedObject.ref(paramVMInterfaceID, m.AssignedObjectID)
	default:
		return nil
	}
}

// ref builds the reference to this interface under the given query parameter.
func (a *assignedObject) ref(param string, id int64) *interfaceRef {
	return &interfaceRef{param: param, id: id, name: a.Name, parent: a.parentName()}
}

// parentName is the device or virtual machine the interface belongs to. It is
// only used in log lines, so a response missing both is named rather than
// treated as an error.
func (a *assignedObject) parentName() string {
	switch {
	case a.Device != nil:
		return a.Device.Name
	case a.VirtualMachine != nil:
		return a.VirtualMachine.Name
	default:
		return "an unnamed parent"
	}
}

// ipAddressPage is the part of a /api/ipam/ip-addresses/ list response we read.
type ipAddressPage struct {
	Results []ipAddress `json:"results"`
}

type ipAddress struct {
	Address string `json:"address"`
}

// lookup resolves mac to the addresses documented on the interface carrying
// it. mac must already be canonical lowercase. A MAC that NetBox does not know,
// or that is not assigned to an interface, is not an error: the result comes
// back with found false.
func (c *client) lookup(ctx context.Context, mac string) (lookupResult, error) {
	ref, err := c.findInterface(ctx, mac)
	if err != nil {
		return lookupResult{}, err
	}
	if ref == nil {
		return lookupResult{}, nil
	}
	return c.addressesFor(ctx, ref)
}

// findInterface asks NetBox which interface owns mac. The first assignment we
// can serve wins; the rest are logged and skipped, because a MAC assigned to
// several objects is a NetBox data problem the DHCP server cannot resolve.
func (c *client) findInterface(ctx context.Context, mac string) (*interfaceRef, error) {
	q := url.Values{}
	q.Set("mac_address", mac)
	q.Set("limit", strconv.Itoa(macAddressLimit))

	var page macAddressPage
	if err := c.get(ctx, macAddressPath, q, &page); err != nil {
		return nil, err
	}
	for i := range page.Results {
		if ref := page.Results[i].interfaceRef(); ref != nil {
			return ref, nil
		}
		log.Debugf("MAC address %s: skipping an entry assigned to %q", mac, page.Results[i].AssignedObjectType)
	}
	return nil, nil
}

// addressesFor collects the first active IPv4 and IPv6 address on ref. One
// query covers both families, since NetBox stores them in the same model.
func (c *client) addressesFor(ctx context.Context, ref *interfaceRef) (lookupResult, error) {
	q := url.Values{}
	q.Set(ref.param, strconv.FormatInt(ref.id, 10))
	q.Set("status", "active")
	q.Set("limit", strconv.Itoa(ipAddressLimit))

	var page ipAddressPage
	if err := c.get(ctx, ipAddressPath, q, &page); err != nil {
		return lookupResult{}, err
	}

	result := lookupResult{found: true}
	for _, addr := range page.Results {
		prefix, err := netip.ParsePrefix(addr.Address)
		if err != nil {
			log.Warningf("ignoring unparseable address %q on interface %s: %v", addr.Address, ref, err)
			continue
		}
		result.record(prefix)
	}
	return result, nil
}

// get performs one authenticated GET and decodes the JSON body into out.
func (c *client) get(ctx context.Context, path string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", path, err)
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return statusError(path, resp.StatusCode)
	}

	// One byte past the limit so a body that is exactly at it still decodes
	// while a longer one is recognisable as truncated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", path, err)
	}
	if len(body) > maxBodyBytes {
		return fmt.Errorf("response from %s is larger than %d bytes", path, maxBodyBytes)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", path, err)
	}
	return nil
}

// statusError describes a non-2xx response. Authentication failures name the
// token, since that is the one thing an operator can act on and the status
// alone reads like a routing mistake.
func statusError(path string, code int) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return fmt.Errorf("%s returned HTTP %d, check the API token and its permissions", path, code)
	}
	return fmt.Errorf("%s returned HTTP %d", path, code)
}
