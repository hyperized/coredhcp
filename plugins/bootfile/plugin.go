// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package bootfile implements a plugin that picks the network boot program
// from the client's architecture, so BIOS, UEFI and HTTP boot machines on the
// same network each get a file they can run.
//
// # Configuration
//
//	server4:
//	  plugins:
//	    - bootfile: x86-bios=tftp://10.0.0.5/undionly.kpxe x86-64-uefi=tftp://10.0.0.5/ipxe.efi arm64-uefi=tftp://10.0.0.5/ipxe-arm64.efi ipxe=http://boot.example/boot.ipxe default=tftp://10.0.0.5/undionly.kpxe
//
// Every argument is one <key>=<url> pair. The order does not matter and each
// entry may be given once. Keys are:
//
//   - an architecture name from the table below, or arch:<n> for any code
//     from 0 to 65535 that has no name here. arch:7 and x86-64-uefi address
//     the same entry, so giving both is a duplicate and fails setup.
//   - ipxe, for a client that is already running iPXE.
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
// Every URL has to parse and use the tftp, http, https or ftp scheme. A bad
// key, a duplicate, a malformed URL or a scheme outside that list fails setup
// naming the offending argument, so a typo stops the server at startup rather
// than handing clients a file they cannot fetch.
//
// # Selection
//
// A client that is already running iPXE gets the ipxe entry when one is
// configured, because iPXE has loaded and should chain to a script instead of
// fetching itself again. It is recognised by the string iPXE in the DHCPv4
// user class (option 77) or at the start of the vendor class (option 60), and
// in the DHCPv6 user class (option 15) or vendor class (option 16).
//
// Otherwise the client's architecture list is walked in the order the client
// sent it and the first configured architecture wins. If none matches, the
// default entry is used. With no default configured the plugin adds nothing
// and the request continues down the chain untouched, which leaves an
// existing nbp or options entry free to answer instead.
//
// # Encoding
//
// The wire encoding is the one the nbp plugin uses, so a single-architecture
// site can move between the two plugins without clients noticing.
//
// For DHCPv4 a tftp URL is split into the TFTP server name (option 66) and
// the bootfile name (option 67), dropping the scheme, the port and anything
// else that is not host and path. An http, https or ftp URL travels whole in
// option 67. Either option is only written when the client listed it in its
// parameter request list.
//
// For DHCPv6 the URL is passed unmodified as OPT_BOOTFILE_URL (option 59). A
// params key in the query string is repeated as OPT_BOOTFILE_PARAM (option
// 60). Both are only written when the client listed them in its ORO.
//
// A client whose architecture is one of the HTTP boot codes also gets the
// vendor class string HTTPClient back: UEFI HTTP Boot ignores a reply that
// does not carry it. For DHCPv4 that is the class identifier (option 60); for
// DHCPv6 it is the vendor class (option 16) under enterprise number 343, the
// pair the UEFI specification defines for HTTP Boot in section 24.3.5.1 and
// that EDK2 looks for when it decides whether an offer is an HTTP offer.
//
// Options this plugin writes replace whatever an earlier plugin set, the same
// last-writer-wins rule the options plugin documents. A request that selects
// no bootfile leaves the response untouched.
//
// # Placement
//
// The plugin does not end the handler chain, so list it wherever the boot
// options belong relative to the rest: after a plugin whose bootfile it
// should override, before one that should override it.
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

// Setup errors that callers and tests can match with errors.Is. Errors that
// have to quote the offending input wrap one of these with fmt.Errorf.
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
	// keyIPXE and keyDefault are the two entries that are not tied to an
	// architecture.
	keyIPXE    = "ipxe"
	keyDefault = "default"

	// archPrefix introduces a numeric architecture code, for the codes the
	// IANA registry has and archNames does not.
	archPrefix = "arch:"

	// ipxeTag is the marker iPXE puts in the class options it sends. iPXE
	// writes it as the whole user class, but a substring match also catches
	// the builds that decorate it, and no other client has a reason to name
	// iPXE at all.
	ipxeTag = "iPXE"

	// httpClient is the vendor class string a UEFI HTTP Boot client expects
	// to see echoed back before it will fetch the bootfile URL.
	httpClient = "HTTPClient"

	// uefiEnterpriseNumber is the IANA private enterprise number the UEFI
	// specification pairs with httpClient in the DHCPv6 vendor class option.
	uefiEnterpriseNumber = 343

	// schemeTFTP is the one scheme DHCPv4 splits over two options.
	schemeTFTP = "tftp"
)

// archNames maps a configuration key to its RFC 4578 architecture code. It is
// an allow-list: a key that is not here and does not start with archPrefix
// fails setup rather than being silently ignored.
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

// httpArchs are the architecture codes whose IANA registry entry says "boot
// from HTTP". A client that reports one of these is doing UEFI HTTP Boot and
// needs the HTTPClient vendor class in the reply. The set is keyed on the
// code, so it covers an entry configured as arch:16 as well as one configured
// as x86-64-http.
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

// bootSchemes is the allow-list of URL schemes a bootfile may use.
var bootSchemes = []string{schemeTFTP, "http", "https", "ftp"}

// httpClientOption and httpClientVendorClass are the replies an HTTP Boot
// client needs to see. Both are built once and shared by every request: the
// handlers only ever read them, so this stays safe with several listeners
// running at the same time.
var (
	httpClientOption = dhcpv4.OptClassIdentifier(httpClient)

	httpClientVendorClass = &dhcpv6.OptVendorClass{
		EnterpriseNumber: uefiEnterpriseNumber,
		Data:             [][]byte{[]byte(httpClient)},
	}
)

// bootFiles is the parsed configuration, before either family compiles it
// into the options it puts on the wire. A nil URL means the entry was not
// configured.
type bootFiles struct {
	byArch map[iana.Arch]*url.URL
	ipxe   *url.URL
	def    *url.URL
}

// count reports how many entries were configured, for the setup log line.
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

// parseArgs turns the configured arguments into a bootFiles.
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

// assign files one parsed entry under its key, refusing a second entry for
// the same target. Duplicates are caught on the resolved architecture rather
// than on the key text, so arch:7 after x86-64-uefi is rejected too.
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

// assignOnce writes u to dst unless dst already holds an entry.
func assignOnce(dst **url.URL, u *url.URL, key string) error {
	if *dst != nil {
		return fmt.Errorf("%q: %w", key, errDuplicateKey)
	}
	*dst = u
	return nil
}

// parseArch resolves a configuration key to an architecture code, by name or
// through the arch:<n> escape hatch.
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

// knownKeys lists the accepted keys for the error message, sorted so the text
// is stable rather than following Go's randomised map iteration.
func knownKeys() string {
	names := make([]string, 0, len(archNames)+3)
	for name := range archNames {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(append(names, keyIPXE, keyDefault, archPrefix+"<n>"), ", ")
}

// parseURL parses one bootfile URL and holds it to the scheme allow-list.
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

// selector holds one protocol family's compiled entries and answers which one
// a request gets. It is read-only once setup returns, so the handlers may run
// concurrently on it.
type selector[T any] struct {
	byArch     map[iana.Arch]T
	ipxe       T
	hasIPXE    bool
	fallback   T
	hasDefault bool
}

// pick chooses the entry for one request. isIPXE reports whether the client
// is already running iPXE, and archs is the architecture list it sent, in the
// order it sent it.
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

// compile turns the parsed configuration into one family's selector, using
// conv to encode a single URL as that family's options.
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

// isHTTPBoot reports whether any architecture the client sent is an HTTP boot
// architecture.
func isHTTPBoot(archs []iana.Arch) bool {
	return slices.ContainsFunc(archs, func(arch iana.Arch) bool {
		_, ok := httpArchs[arch]
		return ok
	})
}

// entry4 is one configured bootfile compiled into the DHCPv4 options that
// carry it. tftpServer is nil for a URL that travels whole in option 67.
type entry4 struct {
	tftpServer *dhcpv4.Option
	bootFile   dhcpv4.Option
}

// newEntry4 encodes one URL the way the nbp plugin encodes it: a tftp URL is
// split over options 66 and 67 with the scheme stripped, everything else goes
// into option 67 unchanged.
func newEntry4(u *url.URL) *entry4 {
	if u.Scheme != schemeTFTP {
		return &entry4{bootFile: dhcpv4.OptBootFileName(u.String())}
	}
	server := dhcpv4.OptTFTPServerName(u.Host)
	return &entry4{tftpServer: &server, bootFile: dhcpv4.OptBootFileName(u.Path)}
}

// apply writes this entry's options into resp, honouring the client's
// parameter request list. archs is passed in rather than read from req again
// because every ClientArch call re-parses the option.
func (e *entry4) apply(req, resp *dhcpv4.DHCPv4, archs []iana.Arch) {
	if e.tftpServer != nil && req.IsOptionRequested(dhcpv4.OptionTFTPServerName) {
		resp.Options.Update(*e.tftpServer)
	}
	if !req.IsOptionRequested(dhcpv4.OptionBootfileName) {
		return
	}
	resp.Options.Update(e.bootFile)
	if isHTTPBoot(archs) {
		// Sent alongside the bootfile rather than gated on the request list:
		// without it an HTTP Boot client discards the reply it just asked
		// for, and it has no meaning on its own.
		resp.Options.Update(httpClientOption)
	}
}

// isIPXE4 reports whether a DHCPv4 client is already running iPXE.
func isIPXE4(req *dhcpv4.DHCPv4) bool {
	if strings.HasPrefix(req.ClassIdentifier(), ipxeTag) {
		return true
	}
	return slices.ContainsFunc(req.UserClass(), func(class string) bool {
		return strings.Contains(class, ipxeTag)
	})
}

// state4 is the DHCPv4 handler's configuration.
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

// entry6 is one configured bootfile compiled into the DHCPv6 options that
// carry it. param is nil unless the URL carries a params query.
type entry6 struct {
	bootFileURL dhcpv6.Option
	param       dhcpv6.Option
}

// newEntry6 encodes one URL the way the nbp plugin encodes it: whole into
// option 59, with a params query repeated into option 60.
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

// apply writes this entry's options into resp, honouring the client's ORO.
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

// isIPXE6 reports whether a DHCPv6 client is already running iPXE.
func isIPXE6(msg *dhcpv6.Message) bool {
	if slices.ContainsFunc(msg.Options.UserClasses(), containsIPXE) {
		return true
	}
	return slices.ContainsFunc(msg.Options.VendorClasses(),
		func(vc *dhcpv6.OptVendorClass) bool {
			return slices.ContainsFunc(vc.Data, containsIPXE)
		})
}

// containsIPXE reports whether one class option value names iPXE.
func containsIPXE(class []byte) bool {
	return strings.Contains(string(class), ipxeTag)
}

// state6 is the DHCPv6 handler's configuration.
type state6 struct {
	sel selector[*entry6]
}

// Handler6 handles DHCPv6 packets for the bootfile plugin.
func (s *state6) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	msg, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("could not decapsulate request: %v", err)
		// Drop the request, this is probably a critical error in the packet.
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

// setup4 builds the DHCPv4 handler.
func setup4(args ...string) (handler.Handler4, error) {
	b, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	s := &state4{sel: compile(b, newEntry4)}
	log.Printf("loaded bootfile plugin for DHCPv4 with %d entries", b.count())
	return s.Handler4, nil
}

// setup6 builds the DHCPv6 handler.
func setup6(args ...string) (handler.Handler6, error) {
	b, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	s := &state6{sel: compile(b, newEntry6)}
	log.Printf("loaded bootfile plugin for DHCPv6 with %d entries", b.count())
	return s.Handler6, nil
}
