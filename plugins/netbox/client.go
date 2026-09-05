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
	// NetBox 4.2 promoted MAC addresses to a model of their own; on anything
	// older this endpoint does not exist.
	macAddressPath = "/api/dcim/mac-addresses/"
	// Filtered by the interface the addresses are assigned to.
	ipAddressPath = "/api/ipam/ip-addresses/"

	// A MAC should be unique, so a few extra rows make a duplicated or
	// unassigned entry visible instead of hiding the assigned one behind it.
	macAddressLimit = 10
	// Only the first address of each family is used, but an interface may
	// legitimately carry several and NetBox' order is the operator's.
	ipAddressLimit = 20

	// assigned_object_type values we can serve addresses for.
	objectTypeInterface   = "dcim.interface"
	objectTypeVMInterface = "virtualization.vminterface"

	// The query parameter naming each object type on the IP address endpoint.
	paramInterfaceID   = "interface_id"
	paramVMInterfaceID = "vminterface_id"

	// The config loader redacts an argument's logged value when it starts with
	// "token:", "password:" or "secret:"; a bare one is printed in full.
	tokenPrefix = "token:"
	// Names an environment variable instead of carrying the secret in config.
	tokenEnvPrefix = "env:"
	// A NetBox 4.5 style token, which authenticates as a bearer token.
	tokenV2Prefix = "nbt_"

	// The list responses are a few kilobytes at most; anything past this is a
	// NetBox bug or something else answering on that URL.
	maxBodyBytes = 1 << 20
)

// Safe for concurrent use: every field is set at construction and read only
// afterwards, and http.Client is itself concurrency-safe.
type client struct {
	base string // no trailing slash, e.g. "https://netbox.example.com"
	auth string // full Authorization header value
	hc   *http.Client
}

// baseURL must already be normalized by parseBaseURL, and token resolved by
// resolveToken.
func newClient(baseURL, token string, timeout time.Duration) *client {
	return &client{
		base: baseURL,
		auth: authHeader(token),
		hc:   &http.Client{Timeout: timeout},
	}
}

// Returned without a trailing slash so paths can be appended directly. A
// subpath is allowed: NetBox is often mounted below the root of its host.
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

// The token: prefix is what makes the config loader treat the argument as a
// secret; a bare literal is accepted for compatibility but gets logged in
// full at startup, hence the warning rather than a silent pass.
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

// arg is the original argument, kept for error messages.
func resolveTaggedToken(arg, rest string) (string, error) {
	if name, ok := strings.CutPrefix(rest, tokenEnvPrefix); ok {
		return resolveEnvToken(arg, name)
	}
	if rest == "" {
		return "", fmt.Errorf("token argument %q needs a token or %sNAME after %q", arg, tokenEnvPrefix, tokenPrefix)
	}
	return rest, nil
}

// arg is the original argument, kept for error messages.
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

// NetBox 4.5 v2 tokens are bearer tokens and carry an "nbt_" prefix; every
// older token uses NetBox' own "Token" scheme.
func authHeader(token string) string {
	if strings.HasPrefix(token, tokenV2Prefix) {
		return "Bearer " + token
	}
	return "Token " + token
}

// The interface may live on a device or on a virtual machine.
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

// Only the fields this plugin reads; everything else NetBox returns is
// ignored.
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

// nil when the MAC is unassigned or attached to something addresses cannot be
// served for, an FHRP group say.
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

func (a *assignedObject) ref(param string, id int64) *interfaceRef {
	return &interfaceRef{param: param, id: id, name: a.Name, parent: a.parentName()}
}

// Only used in log lines, so a response naming neither parent is described
// rather than treated as an error.
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

type ipAddressPage struct {
	Results []ipAddress `json:"results"`
}

type ipAddress struct {
	Address string `json:"address"`
}

// mac must already be canonical lowercase. A MAC NetBox does not know, or one
// assigned to no interface, is not an error: the result has found false.
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

// The first servable assignment wins; the rest are logged and skipped, since a
// MAC on several objects is a NetBox data problem this server cannot resolve.
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

// One query covers both families, since NetBox stores them in the same model.
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

	// One byte past the limit, so a body exactly at it still decodes while a
	// longer one is recognisable as truncated.
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

// An authentication failure names the token: the status alone reads like a
// routing mistake, and the token is what an operator can act on.
func statusError(path string, code int) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return fmt.Errorf("%s returned HTTP %d, check the API token and its permissions", path, code)
	}
	return fmt.Errorf("%s returned HTTP %d", path, code)
}
