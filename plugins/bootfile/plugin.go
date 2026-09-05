// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package bootfile picks the network boot program from the client's
// architecture, so BIOS, UEFI and HTTP boot machines on one network each get
// a file they can run.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - bootfile: x86-bios=tftp://10.0.0.5/undionly.kpxe x86-64-uefi=tftp://10.0.0.5/ipxe.efi arm64-uefi=tftp://10.0.0.5/ipxe-arm64.efi ipxe=http://boot.example/boot.ipxe default=tftp://10.0.0.5/undionly.kpxe
//
// Every argument is one <key>=<url> pair, each key given at most once:
//
//   - an architecture name from the table below, or arch:<n> for a code from
//     0 to 65535. arch:7 and x86-64-uefi are the same entry.
//   - ipxe, for a client already running iPXE.
//   - default, for a client whose architecture matches nothing else.
//
// The named architectures and their RFC 4578 codes:
//
//	x86-bios      0     x86-http      15
//	x86-uefi      6     x86-64-http   16
//	x86-64-uefi   7     arm32-http    18
//	arm32-uefi   10     arm64-http    19
//	arm64-uefi   11     riscv64-uefi  27
//	                    riscv64-http  28
//
// URLs must use the tftp, http, https or ftp scheme. A bad key, a duplicate,
// a malformed URL or another scheme fails setup naming the argument.
//
// # Selection
//
// A client already running iPXE gets the ipxe entry, recognised by the string
// iPXE in the DHCPv4 user class (option 77) or vendor class (option 60), or
// the DHCPv6 user class (option 15) or vendor class (option 16). Otherwise
// the architecture list is walked in the order the client sent it and the
// first configured architecture wins, falling back to default. Without a
// default the request passes through untouched, leaving an nbp or options
// entry further down the chain free to answer instead.
//
// # Encoding
//
// The wire encoding is the nbp plugin's, so a single-architecture site can
// move between the two without clients noticing.
//
// DHCPv4 splits a tftp URL into the TFTP server name (option 66) and bootfile
// name (option 67), keeping only host and path; other schemes travel whole in
// option 67. DHCPv6 passes the URL unmodified as OPT_BOOTFILE_URL (option
// 59), with a params query repeated as OPT_BOOTFILE_PARAM (option 60). Each
// option is written only when the client asked for it.
//
// An HTTP boot architecture also gets the vendor class string HTTPClient,
// without which UEFI HTTP Boot ignores the reply: option 60 for DHCPv4,
// option 16 under enterprise number 343 for DHCPv6, the pair the UEFI
// specification defines in section 24.3.5.1.
//
// Options written here replace whatever an earlier plugin set.
//
// # Placement
//
// The plugin does not end the handler chain: list it after a plugin whose
// bootfile it should override, before one that should override it.
package bootfile

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
)

var log = logger.GetLogger("plugins/bootfile")

// Plugin wraps the bootfile plugin information.
var Plugin = plugins.Plugin{
	Name:   "bootfile",
	Setup6: setup6,
	Setup4: setup4,
}

var (
	errNoEntries      = errors.New("need at least one <key>=<url> entry")
	errMalformedEntry = errors.New("expected <key>=<url>")
	errUnknownKey     = errors.New("unknown key")
	errBadArchCode    = errors.New("architecture code must be a number from 0 to 65535")
	errDuplicateKey   = errors.New("configured twice")
	errBadURL         = errors.New("unparseable URL")
	errBadScheme      = errors.New("unsupported URL scheme")
)

const (
	keyIPXE    = "ipxe"
	keyDefault = "default"
	archPrefix = "arch:"

	// Matched as a substring: iPXE builds decorate the class string, and no
	// other client has a reason to name iPXE at all.
	ipxeTag = "iPXE"

	// Echoed back to a UEFI HTTP Boot client, which discards replies without it.
	httpClient = "HTTPClient"

	// IANA private enterprise number the UEFI spec pairs with httpClient.
	uefiEnterpriseNumber = 343

	// The one scheme DHCPv4 splits over two options.
	schemeTFTP = "tftp"
)

// Allow-list: a key absent here and without the archPrefix fails setup rather
// than being silently ignored.
var archNames = map[string]iana.Arch{
	"x86-bios":     iana.INTEL_X86PC,
	"x86-uefi":     iana.EFI_IA32,
	"x86-64-uefi":  iana.EFI_X86_64,
	"arm32-uefi":   iana.EFI_ARM32,
	"arm64-uefi":   iana.EFI_ARM64,
	"x86-http":     iana.EFI_X86_HTTP,
	"x86-64-http":  iana.EFI_X86_64_HTTP,
	"arm32-http":   iana.EFI_ARM32_HTTP,
	"arm64-http":   iana.EFI_ARM64_HTTP,
	"riscv64-uefi": iana.EFI_RISCV64,
	"riscv64-http": iana.EFI_RISCV64_HTTP,
}

// Architectures needing the HTTPClient vendor class. Keyed on the code so
// arch:16 is covered as well as x86-64-http.
var httpArchs = map[iana.Arch]struct{}{
	iana.EFI_X86_HTTP:      {},
	iana.EFI_X86_64_HTTP:   {},
	iana.EFI_BC_HTTP:       {},
	iana.EFI_ARM32_HTTP:    {},
	iana.EFI_ARM64_HTTP:    {},
	iana.INTEL_X86PC_HTTP:  {},
	iana.UBOOT_ARM32_HTTP:  {},
	iana.UBOOT_ARM64_HTTP:  {},
	iana.EFI_RISCV32_HTTP:  {},
	iana.EFI_RISCV64_HTTP:  {},
	iana.EFI_RISCV128_HTTP: {},
}

var bootSchemes = []string{schemeTFTP, "http", "https", "ftp"}

// Built once and shared by every request; handlers only read them, so this is
// safe with several listeners running.
var (
	httpClientOption = dhcpv4.OptClassIdentifier(httpClient)

	httpClientVendorClass = &dhcpv6.OptVendorClass{
		EnterpriseNumber: uefiEnterpriseNumber,
		Data:             [][]byte{[]byte(httpClient)},
	}
)

// Parsed configuration, before either family compiles it into wire options. A
// nil URL means the entry was not configured.
type bootFiles struct {
	byArch map[iana.Arch]*url.URL
	ipxe   *url.URL
	def    *url.URL
}

func (b *bootFiles) count() int {
	n := len(b.byArch)
	if b.ipxe != nil {
		n++
	}
	if b.def != nil {
		n++
	}
	return n
}

func parseArgs(args ...string) (*bootFiles, error) {
	if len(args) == 0 {
		return nil, errNoEntries
	}
	b := &bootFiles{byArch: make(map[iana.Arch]*url.URL, len(args))}
	for _, arg := range args {
		key, raw, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("%q: %w", arg, errMalformedEntry)
		}
		u, err := parseURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", key, err)
		}
		if err := b.assign(key, u); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Duplicates are caught on the resolved architecture rather than the key text,
// so arch:7 after x86-64-uefi is rejected too.
func (b *bootFiles) assign(key string, u *url.URL) error {
	switch key {
	case keyIPXE:
		return assignOnce(&b.ipxe, u, key)
	case keyDefault:
		return assignOnce(&b.def, u, key)
	}
	arch, err := parseArch(key)
	if err != nil {
		return err
	}
	if _, dup := b.byArch[arch]; dup {
		return fmt.Errorf("%q (architecture %d): %w", key, uint16(arch), errDuplicateKey)
	}
	b.byArch[arch] = u
	return nil
}

func assignOnce(dst **url.URL, u *url.URL, key string) error {
	if *dst != nil {
		return fmt.Errorf("%q: %w", key, errDuplicateKey)
	}
	*dst = u
	return nil
}

func parseArch(key string) (iana.Arch, error) {
	if arch, ok := archNames[key]; ok {
		return arch, nil
	}
	digits, ok := strings.CutPrefix(key, archPrefix)
	if !ok {
		return 0, fmt.Errorf("%q: %w (known keys: %s)", key, errUnknownKey, knownKeys())
	}
	code, err := strconv.ParseUint(digits, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q: %w", key, errBadArchCode)
	}
	return iana.Arch(code), nil
}

// Sorted so the error text is stable rather than following map iteration order.
func knownKeys() string {
	names := make([]string, 0, len(archNames)+3)
	for name := range archNames {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(append(names, keyIPXE, keyDefault, archPrefix+"<n>"), ", ")
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadURL, err)
	}
	if !slices.Contains(bootSchemes, u.Scheme) {
		return nil, fmt.Errorf("%w %q (want one of: %s)", errBadScheme, u.Scheme,
			strings.Join(bootSchemes, ", "))
	}
	return u, nil
}

// Read-only once setup returns, so handlers may run concurrently on it.
type selector[T any] struct {
	byArch     map[iana.Arch]T
	ipxe       T
	hasIPXE    bool
	fallback   T
	hasDefault bool
}

// archs is in the order the client sent it, which sets the match priority.
func (s *selector[T]) pick(isIPXE bool, archs []iana.Arch) (T, bool) {
	if isIPXE && s.hasIPXE {
		return s.ipxe, true
	}
	for _, arch := range archs {
		if entry, ok := s.byArch[arch]; ok {
			return entry, true
		}
	}
	if s.hasDefault {
		return s.fallback, true
	}
	var none T
	return none, false
}

func compile[T any](b *bootFiles, conv func(*url.URL) T) selector[T] {
	s := selector[T]{byArch: make(map[iana.Arch]T, len(b.byArch))}
	for arch, u := range b.byArch {
		s.byArch[arch] = conv(u)
	}
	if b.ipxe != nil {
		s.ipxe, s.hasIPXE = conv(b.ipxe), true
	}
	if b.def != nil {
		s.fallback, s.hasDefault = conv(b.def), true
	}
	return s
}

func isHTTPBoot(archs []iana.Arch) bool {
	return slices.ContainsFunc(archs, func(arch iana.Arch) bool {
		_, ok := httpArchs[arch]
		return ok
	})
}

// tftpServer is nil for a URL that travels whole in option 67.
type entry4 struct {
	tftpServer *dhcpv4.Option
	bootFile   dhcpv4.Option
}

func newEntry4(u *url.URL) *entry4 {
	if u.Scheme != schemeTFTP {
		return &entry4{bootFile: dhcpv4.OptBootFileName(u.String())}
	}
	server := dhcpv4.OptTFTPServerName(u.Host)
	return &entry4{tftpServer: &server, bootFile: dhcpv4.OptBootFileName(u.Path)}
}

// archs is passed in rather than re-read from req, as ClientArch re-parses the
// option on every call.
func (e *entry4) apply(req, resp *dhcpv4.DHCPv4, archs []iana.Arch) {
	if e.tftpServer != nil && req.IsOptionRequested(dhcpv4.OptionTFTPServerName) {
		resp.Options.Update(*e.tftpServer)
	}
	if !req.IsOptionRequested(dhcpv4.OptionBootfileName) {
		return
	}
	resp.Options.Update(e.bootFile)
	if isHTTPBoot(archs) {
		// Not gated on the request list: without it an HTTP Boot client
		// discards the reply it just asked for.
		resp.Options.Update(httpClientOption)
	}
}

func isIPXE4(req *dhcpv4.DHCPv4) bool {
	if strings.HasPrefix(req.ClassIdentifier(), ipxeTag) {
		return true
	}
	return slices.ContainsFunc(req.UserClass(), func(class string) bool {
		return strings.Contains(class, ipxeTag)
	})
}

type state4 struct {
	sel selector[*entry4]
}

// Handler4 handles DHCPv4 packets for the bootfile plugin.
func (s *state4) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	archs := req.ClientArch()
	entry, ok := s.sel.pick(isIPXE4(req), archs)
	if !ok {
		log.Debugf("no bootfile configured for %s", iana.Archs(archs))
		return resp, false
	}
	entry.apply(req, resp, archs)
	return resp, false
}

// param is nil unless the URL carries a params query.
type entry6 struct {
	bootFileURL dhcpv6.Option
	param       dhcpv6.Option
}

func newEntry6(u *url.URL) *entry6 {
	e := &entry6{bootFileURL: dhcpv6.OptBootFileURL(u.String())}
	if params := u.Query().Get("params"); params != "" {
		e.param = &dhcpv6.OptionGeneric{
			OptionCode: dhcpv6.OptionBootfileParam,
			OptionData: []byte(params),
		}
	}
	return e
}

func (e *entry6) apply(requested dhcpv6.OptionCodes, resp dhcpv6.DHCPv6, archs []iana.Arch) {
	if e.param != nil && requested.Contains(dhcpv6.OptionBootfileParam) {
		resp.UpdateOption(e.param)
	}
	if !requested.Contains(dhcpv6.OptionBootfileURL) {
		return
	}
	resp.UpdateOption(e.bootFileURL)
	if isHTTPBoot(archs) {
		resp.UpdateOption(httpClientVendorClass)
	}
}

func isIPXE6(msg *dhcpv6.Message) bool {
	if slices.ContainsFunc(msg.Options.UserClasses(), containsIPXE) {
		return true
	}
	return slices.ContainsFunc(msg.Options.VendorClasses(),
		func(vc *dhcpv6.OptVendorClass) bool {
			return slices.ContainsFunc(vc.Data, containsIPXE)
		})
}

func containsIPXE(class []byte) bool {
	return strings.Contains(string(class), ipxeTag)
}

type state6 struct {
	sel selector[*entry6]
}

// Handler6 handles DHCPv6 packets for the bootfile plugin.
func (s *state6) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("could not decapsulate request: %v", err)
		return nil, true
	}
	archs := msg.Options.ArchTypes()
	entry, ok := s.sel.pick(isIPXE6(msg), archs)
	if !ok {
		log.Debugf("no bootfile configured for %s", archs)
		return resp, false
	}
	entry.apply(msg.Options.RequestedOptions(), resp, archs)
	return resp, false
}

func setup4(args ...string) (handler.Handler4, error) {
	b, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	s := &state4{sel: compile(b, newEntry4)}
	log.Printf("loaded bootfile plugin for DHCPv4 with %d entries", b.count())
	return s.Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	b, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	s := &state6{sel: compile(b, newEntry6)}
	log.Printf("loaded bootfile plugin for DHCPv6 with %d entries", b.count())
	return s.Handler6, nil
}
