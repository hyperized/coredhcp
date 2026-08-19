// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package options implements a plugin that sets arbitrary DHCP options on
// responses, for the many options that do not warrant a plugin of their own.
//
// Every argument is one option specification of the form `code:type:value`,
// and the plugin is repeatable:
//
//	server4:
//	  plugins:
//	    - options: 15:string:home.lan 42:ip:192.0.2.10
//
// The specification is split on the first two colons only, so a value may
// itself contain colons, as IPv6 addresses and URLs do.
//
// The type names an encoder from a fixed allow-list (string, ip, iplist,
// uint8, uint16, uint32, hex, bool); everything is validated at setup time so
// a typo in the configuration fails the server at startup instead of emitting
// a malformed packet later. Codes must fit the protocol: 1-255 for DHCPv4,
// 1-65535 for DHCPv6. Code 0 is the DHCPv4 pad option and is rejected in both
// families.
//
// Options are set unconditionally, exactly like the dns and router plugins do,
// and deliberately not conditioned on the client's parameter request list:
// a client cannot ask for an option it has never heard of, so honouring the
// request list would make this plugin useless for the vendor and site-local
// options it exists to serve.
//
// No option code is blocked. Setting a code the server manages elsewhere
// (51 lease time, 54 server identifier, 1 subnet mask, 3 router) is the
// operator's own foot to shoot, and plugin order decides the winner: handlers
// run in configuration order and each one overwrites what came before, so an
// `options` entry placed after the `lease_time` plugin overrides it, and one
// placed before it does not. DHCPv4 code 255 is the end marker and setting it
// will corrupt the packet.
package options

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/options")

// Plugin wraps the options plugin information.
var Plugin = plugins.Plugin{
	Name:   "options",
	Setup6: setup6,
	Setup4: setup4,
}

// Setup errors that callers and tests can match with errors.Is. Errors that
// need to quote the offending input are built with fmt.Errorf instead.
var (
	errNoSpecs       = errors.New("need at least one option specification")
	errMalformedSpec = errors.New("expected code:type:value")
	errZeroCode      = errors.New("option code 0 is the pad option and cannot be set")
	errEmptyValue    = errors.New("empty option value")
)

// specFields is the number of colon-separated fields in one specification.
// SplitN is called with this limit so that everything after the second colon
// stays in the value.
const specFields = 3

// family holds the validation rules that differ between DHCPv4 and DHCPv6.
type family struct {
	// maxCode is the largest option code the protocol can encode.
	maxCode uint64
	// parseAddr parses one textual address into its wire representation:
	// four bytes for DHCPv4, sixteen for DHCPv6.
	parseAddr func(string) ([]byte, error)
}

var family4 = &family{maxCode: math.MaxUint8, parseAddr: parseAddr4}

var family6 = &family{maxCode: math.MaxUint16, parseAddr: parseAddr6}

// parseAddr4 accepts any address with an IPv4 representation and returns it in
// four-byte form, which is what DHCPv4 options carry.
func parseAddr4(value string) ([]byte, error) {
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return nil, fmt.Errorf("expected an IPv4 address, got %q", value)
	}
	return ip, nil
}

// parseAddr6 accepts native IPv6 addresses only. An IPv4 literal would happily
// survive To16() as a v4-mapped address, but a v4 address in a DHCPv6 option is
// a configuration mistake in every case worth serving, so it is rejected.
func parseAddr6(value string) ([]byte, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("expected an IPv6 address, got %q", value)
	}
	return ip.To16(), nil
}

// valueParser converts the textual value of one specification into the bytes
// that go on the wire. fam supplies the protocol-dependent address parsing.
type valueParser func(fam *family, value string) ([]byte, error)

// valueParsers is the allow-list of value types. A type that is not a key here
// is rejected at setup; there is no fallback encoding.
var valueParsers = map[string]valueParser{
	"string": parseStringValue,
	"ip":     parseIPValue,
	"iplist": parseIPListValue,
	"uint8":  uintParser(8),
	"uint16": uintParser(16),
	"uint32": uintParser(32),
	"hex":    parseHexValue,
	"bool":   parseBoolValue,
}

// knownTypes lists the supported type names, sorted so error messages are
// stable rather than following Go's randomised map iteration.
func knownTypes() string {
	names := make([]string, 0, len(valueParsers))
	for name := range valueParsers {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// parseStringValue emits the value as-is. DHCP strings are not NUL-terminated.
func parseStringValue(_ *family, value string) ([]byte, error) {
	return []byte(value), nil
}

func parseIPValue(fam *family, value string) ([]byte, error) {
	return fam.parseAddr(value)
}

// parseIPListValue encodes a comma-separated list as the concatenation of the
// addresses, the layout every list-of-addresses option uses.
func parseIPListValue(fam *family, value string) ([]byte, error) {
	parts := strings.Split(value, ",")
	// Parsing happens once at setup, so sizing for the IPv6 worst case is
	// cheaper than carrying the address width around.
	out := make([]byte, 0, len(parts)*net.IPv6len)
	for _, part := range parts {
		addr, err := fam.parseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, addr...)
	}
	return out, nil
}

// uintParser builds a parser for an unsigned integer of the given width in
// bits. DHCP numeric options are fixed-width and big-endian (RFC 2132 section
// 2), so the value is right-aligned into a width/8 byte buffer.
func uintParser(bits int) valueParser {
	width := bits / 8
	return func(_ *family, value string) ([]byte, error) {
		n, err := strconv.ParseUint(value, 10, bits)
		if err != nil {
			return nil, fmt.Errorf("invalid uint%d value %q: %w", bits, value, err)
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], n)
		return buf[8-width:], nil
	}
}

// parseHexValue decodes raw option bytes. hex.DecodeString is what enforces an
// even-length string of hex digits.
func parseHexValue(_ *family, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid hex value %q: %w", value, err)
	}
	return raw, nil
}

// parseBoolValue encodes a boolean as the single byte 0 or 1, the convention of
// the flag options (RFC 2132 sections 4.1 through 4.5). It accepts everything
// strconv.ParseBool does, so "1", "t", "TRUE" and friends all work.
func parseBoolValue(_ *family, value string) ([]byte, error) {
	set, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("invalid bool value %q: %w", value, err)
	}
	if set {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// spec is one parsed specification: an option code and the exact bytes to put
// on the wire for it.
type spec struct {
	code uint16
	data []byte
}

// parseCode validates an option code against the protocol's range.
func parseCode(fam *family, raw string) (uint16, error) {
	code, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid option code %q: %w", raw, err)
	}
	if code == 0 {
		return 0, errZeroCode
	}
	if code > fam.maxCode {
		return 0, fmt.Errorf("option code %d out of range, want 1-%d", code, fam.maxCode)
	}
	return uint16(code), nil
}

// parseSpec parses one `code:type:value` argument.
func parseSpec(fam *family, arg string) (spec, error) {
	fields := strings.SplitN(arg, ":", specFields)
	if len(fields) != specFields {
		return spec{}, errMalformedSpec
	}
	code, err := parseCode(fam, fields[0])
	if err != nil {
		return spec{}, err
	}
	parse, ok := valueParsers[fields[1]]
	if !ok {
		return spec{}, fmt.Errorf("unknown type %q, want one of: %s", fields[1], knownTypes())
	}
	if fields[2] == "" {
		return spec{}, errEmptyValue
	}
	data, err := parse(fam, fields[2])
	if err != nil {
		return spec{}, err
	}
	return spec{code: code, data: data}, nil
}

// parseSpecs parses every configured argument, keeping configuration order so
// that a code repeated within one plugin instance resolves last-one-wins.
func parseSpecs(fam *family, args []string) ([]spec, error) {
	if len(args) == 0 {
		return nil, errNoSpecs
	}
	specs := make([]spec, 0, len(args))
	for _, arg := range args {
		parsed, err := parseSpec(fam, arg)
		if err != nil {
			return nil, fmt.Errorf("invalid option specification %q: %w", arg, err)
		}
		specs = append(specs, parsed)
	}
	return specs, nil
}

// pluginState holds the options handed out by one setup instance of the
// plugin. Everything in it is built during setup and only read afterwards, so
// a single instance is safe for concurrent use by the server's handler chain.
type pluginState struct {
	// opts4 holds ready-made DHCPv4 options. dhcpv4.Options.Update copies the
	// option's bytes into the response's map immediately, so one prebuilt
	// value can serve every response without aliasing anything into it.
	opts4 []dhcpv4.Option
	// specs6 holds parsed DHCPv6 specifications rather than ready-made
	// options: a DHCPv6 response stores the Option pointer it is handed, so
	// Handler6 wraps the payload in a fresh OptionGeneric per response instead
	// of sharing one struct between packets in flight.
	specs6 []spec
}

func setup4(args ...string) (handler.Handler4, error) {
	specs, err := parseSpecs(family4, args)
	if err != nil {
		return nil, err
	}
	p := pluginState{opts4: make([]dhcpv4.Option, 0, len(specs))}
	for _, s := range specs {
		// parseCode already bounded the code to family4.maxCode (255), so the
		// narrowing conversion cannot overflow.
		code := dhcpv4.GenericOptionCode(s.code) //nolint:gosec // bounded by parseCode against family4.maxCode
		p.opts4 = append(p.opts4, dhcpv4.OptGeneric(code, s.data))
	}
	log.Infof("loaded %d DHCPv4 options.", len(p.opts4))
	return p.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	specs, err := parseSpecs(family6, args)
	if err != nil {
		return nil, err
	}
	p := pluginState{specs6: specs}
	log.Infof("loaded %d DHCPv6 options.", len(p.specs6))
	return p.Handler6, nil
}

// Handler4 handles DHCPv4 packets for the options plugin.
func (p *pluginState) Handler4(_, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	for _, opt := range p.opts4 {
		resp.Options.Update(opt)
	}
	return resp, false
}

// Handler6 handles DHCPv6 packets for the options plugin.
func (p *pluginState) Handler6(_, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	for _, s := range p.specs6 {
		resp.UpdateOption(&dhcpv6.OptionGeneric{
			OptionCode: dhcpv6.OptionCode(s.code),
			OptionData: s.data,
		})
	}
	return resp, false
}
