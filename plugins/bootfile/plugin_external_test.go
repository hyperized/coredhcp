// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package bootfile_test

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/bootfile"
)

const (
	biosFile  = "tftp://10.0.0.5/undionly.kpxe"
	uefiFile  = "tftp://10.0.0.5/ipxe.efi"
	armFile   = "tftp://10.0.0.5/ipxe-arm64.efi"
	httpFile  = "http://boot.example/ipxe.efi"
	scriptURL = "http://boot.example/boot.ipxe"
	httpClass = "HTTPClient"
)

// fullConfig covers a mixed network: BIOS, UEFI on two architectures, UEFI
// HTTP boot, an iPXE script and a catch-all.
var fullConfig = []string{
	"x86-bios=" + biosFile,
	"x86-64-uefi=" + uefiFile,
	"arm64-uefi=" + armFile,
	"x86-64-http=" + httpFile,
	"ipxe=" + scriptURL,
	"default=" + biosFile,
}

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

func TestPluginRegistration(t *testing.T) {
	assert.Equal(t, "bootfile", bootfile.Plugin.Name)
	assert.NotNil(t, bootfile.Plugin.Setup4)
	assert.NotNil(t, bootfile.Plugin.Setup6)
	assert.Nil(t, bootfile.Plugin.Setup4Ctx)
	assert.Nil(t, bootfile.Plugin.Setup6Ctx)
}

func TestSetupArgValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"missing equals sign", []string{"x86-bios"}},
		{"unknown key", []string{"sparc=tftp://10.0.0.5/f"}},
		{"unparseable architecture code", []string{"arch:efi=tftp://10.0.0.5/f"}},
		{"malformed URL", []string{"x86-bios=tftp://[::1"}},
		{"unsupported scheme", []string{"x86-bios=nfs://10.0.0.5/f"}},
		{"duplicate key", []string{"ipxe=http://a/s", "ipxe=http://b/s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h4, err := bootfile.Plugin.Setup4(tc.args...)
			assert.Nil(t, h4)
			require.Error(t, err)

			h6, err := bootfile.Plugin.Setup6(tc.args...)
			assert.Nil(t, h6)
			require.Error(t, err)
		})
	}
}

// request4 describes the DHCPv4 request one table case sends.
type request4 struct {
	archs     []iana.Arch
	prl       []dhcpv4.OptionCode
	noPRL     bool
	userClass string
	classID   string
}

func (r request4) build(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	mods := []dhcpv4.Modifier{}
	if r.noPRL {
		// RFC 2131 section 3.5: a client that sends no parameter request
		// list is asking for everything the server has.
		mods = append(mods, dhcpv4.WithoutOption(dhcpv4.OptionParameterRequestList))
	}
	req, err := dhcpv4.NewDiscovery(testMAC, mods...)
	require.NoError(t, err)
	if !r.noPRL {
		req.UpdateOption(dhcpv4.OptParameterRequestList(r.prl...))
	}
	if len(r.archs) > 0 {
		req.UpdateOption(dhcpv4.OptClientArch(r.archs...))
	}
	if r.userClass != "" {
		req.UpdateOption(dhcpv4.OptUserClass(r.userClass))
	}
	if r.classID != "" {
		req.UpdateOption(dhcpv4.OptClassIdentifier(r.classID))
	}
	return req
}

func TestHandler4(t *testing.T) {
	bootOptions := []dhcpv4.OptionCode{dhcpv4.OptionTFTPServerName, dhcpv4.OptionBootfileName}

	for _, tc := range []struct {
		name         string
		args         []string
		req          request4
		wantTFTP     string
		wantBootFile string
		wantClassID  string
	}{
		{
			name:         "bios client gets the tftp url split over two options",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.INTEL_X86PC}, prl: bootOptions},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/undionly.kpxe",
		},
		{
			name:         "uefi x86-64",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.EFI_X86_64}, prl: bootOptions},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/ipxe.efi",
		},
		{
			name:         "uefi arm64",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.EFI_ARM64}, prl: bootOptions},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/ipxe-arm64.efi",
		},
		{
			name:         "http boot keeps the url whole and asks for HTTPClient",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.EFI_X86_64_HTTP}, prl: bootOptions},
			wantBootFile: httpFile,
			wantClassID:  httpClass,
		},
		{
			name:         "numeric architecture key",
			args:         []string{"arch:27=" + uefiFile},
			req:          request4{archs: []iana.Arch{iana.EFI_RISCV64}, prl: bootOptions},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/ipxe.efi",
		},
		{
			name: "first configured architecture in the client's list wins",
			args: fullConfig,
			req: request4{
				archs: []iana.Arch{iana.EFI_ITANIUM, iana.EFI_ARM64, iana.EFI_X86_64},
				prl:   bootOptions,
			},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/ipxe-arm64.efi",
		},
		{
			name:         "ipxe user class beats the architecture",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.EFI_X86_64}, prl: bootOptions, userClass: "iPXE"},
			wantBootFile: scriptURL,
		},
		{
			name:         "ipxe vendor class beats the architecture",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.EFI_X86_64}, prl: bootOptions, classID: "iPXE"},
			wantBootFile: scriptURL,
		},
		{
			name:         "unconfigured architecture falls back to default",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.DEC_ALPHA}, prl: bootOptions},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/undionly.kpxe",
		},
		{
			name: "an http client served by default still gets HTTPClient",
			args: []string{"default=" + httpFile},
			req: request4{
				archs: []iana.Arch{iana.EFI_ARM64_HTTP},
				prl:   bootOptions,
			},
			wantBootFile: httpFile,
			wantClassID:  httpClass,
		},
		{
			name: "no match and no default adds nothing",
			args: []string{"x86-bios=" + biosFile},
			req:  request4{archs: []iana.Arch{iana.EFI_X86_64}, prl: bootOptions},
		},
		{
			name: "neither boot option requested",
			args: fullConfig,
			req:  request4{archs: []iana.Arch{iana.INTEL_X86PC}, prl: []dhcpv4.OptionCode{dhcpv4.OptionSubnetMask}},
		},
		{
			name:     "only the tftp server name requested",
			args:     fullConfig,
			req:      request4{archs: []iana.Arch{iana.INTEL_X86PC}, prl: []dhcpv4.OptionCode{dhcpv4.OptionTFTPServerName}},
			wantTFTP: "10.0.0.5",
		},
		{
			name:         "tftp server name not requested",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.INTEL_X86PC}, prl: []dhcpv4.OptionCode{dhcpv4.OptionBootfileName}},
			wantBootFile: "/undionly.kpxe",
		},
		{
			// An http url is never split, and a client that boots over
			// tftp gets no HTTPClient even when the file is fetched by
			// http, because it is the architecture that decides.
			name:         "http url on a tftp architecture",
			args:         []string{"x86-64-uefi=" + httpFile},
			req:          request4{archs: []iana.Arch{iana.EFI_X86_64}, prl: bootOptions},
			wantBootFile: httpFile,
		},
		{
			name:         "no parameter request list means everything is requested",
			args:         fullConfig,
			req:          request4{archs: []iana.Arch{iana.INTEL_X86PC}, noPRL: true},
			wantTFTP:     "10.0.0.5",
			wantBootFile: "/undionly.kpxe",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := bootfile.Plugin.Setup4(tc.args...)
			require.NoError(t, err)

			req := tc.req.build(t)
			stub, err := dhcpv4.NewReplyFromRequest(req)
			require.NoError(t, err)

			resp, stop := h(req, stub)
			require.NotNil(t, resp)
			assert.False(t, stop, "the plugin must not end the handler chain")
			assert.Equal(t, tc.wantTFTP, resp.TFTPServerName())
			assert.Equal(t, tc.wantBootFile, resp.BootFileNameOption())
			assert.Equal(t, tc.wantClassID, resp.ClassIdentifier())
		})
	}
}

func TestHandler4OverwritesOnlyWhenItSelects(t *testing.T) {
	h, err := bootfile.Plugin.Setup4("x86-bios=" + biosFile)
	require.NoError(t, err)

	t.Run("a selected bootfile replaces what an earlier plugin set", func(t *testing.T) {
		req := request4{
			archs: []iana.Arch{iana.INTEL_X86PC},
			prl:   []dhcpv4.OptionCode{dhcpv4.OptionBootfileName},
		}.build(t)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		stub.UpdateOption(dhcpv4.OptBootFileName("/earlier"))

		resp, _ := h(req, stub)
		assert.Equal(t, "/undionly.kpxe", resp.BootFileNameOption())
	})

	t.Run("no selection leaves what an earlier plugin set", func(t *testing.T) {
		req := request4{
			archs: []iana.Arch{iana.EFI_X86_64},
			prl:   []dhcpv4.OptionCode{dhcpv4.OptionBootfileName},
		}.build(t)
		stub, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		stub.UpdateOption(dhcpv4.OptBootFileName("/earlier"))

		resp, _ := h(req, stub)
		assert.Equal(t, "/earlier", resp.BootFileNameOption())
	})
}

const (
	uefiFile6  = "tftp://[2001:db8::5]/ipxe.efi"
	httpFile6  = "http://[2001:db8::5]/ipxe.efi"
	script6    = "http://[2001:db8::5]/boot.ipxe"
	defFile6   = "tftp://[2001:db8::5]/undionly.kpxe"
	paramFile6 = "tftp://[2001:db8::5]/ipxe.efi?params=console=ttyS0"
)

var fullConfig6 = []string{
	"x86-64-uefi=" + uefiFile6,
	"x86-64-http=" + httpFile6,
	"ipxe=" + script6,
	"default=" + defFile6,
}

// request6 describes the DHCPv6 request one table case sends.
type request6 struct {
	archs   []iana.Arch
	oro     []dhcpv6.OptionCode
	options []dhcpv6.Option
}

func (r request6) build(t *testing.T) *dhcpv6.Message {
	t.Helper()
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	if len(r.oro) > 0 {
		req.AddOption(dhcpv6.OptRequestedOption(r.oro...))
	}
	if len(r.archs) > 0 {
		req.AddOption(dhcpv6.OptClientArchType(r.archs...))
	}
	for _, opt := range r.options {
		req.AddOption(opt)
	}
	return req
}

func TestHandler6(t *testing.T) {
	bootOptions := []dhcpv6.OptionCode{dhcpv6.OptionBootfileURL, dhcpv6.OptionBootfileParam}

	for _, tc := range []struct {
		name            string
		args            []string
		req             request6
		wantURL         string
		wantParam       string
		wantVendorClass bool
	}{
		{
			name:    "uefi client",
			args:    fullConfig6,
			req:     request6{archs: []iana.Arch{iana.EFI_X86_64}, oro: bootOptions},
			wantURL: uefiFile6,
		},
		{
			name:            "http boot client also gets the vendor class",
			args:            fullConfig6,
			req:             request6{archs: []iana.Arch{iana.EFI_X86_64_HTTP}, oro: bootOptions},
			wantURL:         httpFile6,
			wantVendorClass: true,
		},
		{
			name:    "first configured architecture in the client's list wins",
			args:    fullConfig6,
			req:     request6{archs: []iana.Arch{iana.EFI_ARM64, iana.EFI_X86_64}, oro: bootOptions},
			wantURL: uefiFile6,
		},
		{
			name: "ipxe user class beats the architecture",
			args: fullConfig6,
			req: request6{
				archs:   []iana.Arch{iana.EFI_X86_64},
				oro:     bootOptions,
				options: []dhcpv6.Option{&dhcpv6.OptUserClass{UserClasses: [][]byte{[]byte("iPXE")}}},
			},
			wantURL: script6,
		},
		{
			name: "ipxe vendor class beats the architecture",
			args: fullConfig6,
			req: request6{
				archs: []iana.Arch{iana.EFI_X86_64},
				oro:   bootOptions,
				options: []dhcpv6.Option{
					&dhcpv6.OptVendorClass{EnterpriseNumber: 343, Data: [][]byte{[]byte("iPXE")}},
				},
			},
			wantURL: script6,
		},
		{
			name:    "unconfigured architecture falls back to default",
			args:    fullConfig6,
			req:     request6{archs: []iana.Arch{iana.DEC_ALPHA}, oro: bootOptions},
			wantURL: defFile6,
		},
		{
			name: "no match and no default adds nothing",
			args: []string{"x86-64-uefi=" + uefiFile6},
			req:  request6{archs: []iana.Arch{iana.EFI_ARM64}, oro: bootOptions},
		},
		{
			name: "bootfile url not requested",
			args: fullConfig6,
			req: request6{
				archs: []iana.Arch{iana.EFI_X86_64},
				oro:   []dhcpv6.OptionCode{dhcpv6.OptionDNSRecursiveNameServer},
			},
		},
		{
			name:      "params are repeated into option 60",
			args:      []string{"x86-64-uefi=" + paramFile6},
			req:       request6{archs: []iana.Arch{iana.EFI_X86_64}, oro: bootOptions},
			wantURL:   paramFile6,
			wantParam: "console=ttyS0",
		},
		{
			name: "params requested without the url",
			args: []string{"x86-64-uefi=" + paramFile6},
			req: request6{
				archs: []iana.Arch{iana.EFI_X86_64},
				oro:   []dhcpv6.OptionCode{dhcpv6.OptionBootfileParam},
			},
			wantParam: "console=ttyS0",
		},
		{
			name: "no params configured means no option 60",
			args: fullConfig6,
			req:  request6{archs: []iana.Arch{iana.EFI_X86_64}, oro: bootOptions},

			wantURL: uefiFile6,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := bootfile.Plugin.Setup6(tc.args...)
			require.NoError(t, err)

			stub, err := dhcpv6.NewMessage()
			require.NoError(t, err)

			resp, stop := h(tc.req.build(t), stub)
			require.NotNil(t, resp)
			assert.False(t, stop, "the plugin must not end the handler chain")

			assertOption6(t, resp, dhcpv6.OptionBootfileURL, tc.wantURL)
			assertOption6(t, resp, dhcpv6.OptionBootfileParam, tc.wantParam)

			vendor := resp.GetOneOption(dhcpv6.OptionVendorClass)
			if !tc.wantVendorClass {
				assert.Nil(t, vendor)
				return
			}
			opt, ok := vendor.(*dhcpv6.OptVendorClass)
			require.True(t, ok)
			assert.Equal(t, uint32(343), opt.EnterpriseNumber)
			assert.Equal(t, [][]byte{[]byte(httpClass)}, opt.Data)
		})
	}
}

// assertOption6 checks one option's value, where the empty string means the
// option must be absent.
func assertOption6(t *testing.T, resp dhcpv6.DHCPv6, code dhcpv6.OptionCode, want string) {
	t.Helper()
	opt := resp.GetOneOption(code)
	if want == "" {
		assert.Nil(t, opt)
		return
	}
	require.NotNil(t, opt)
	assert.Equal(t, want, string(opt.ToBytes()))
}

func TestHandler6DecapsulateError(t *testing.T) {
	h, err := bootfile.Plugin.Setup6("default=" + defFile6)
	require.NoError(t, err)

	// A relay-forward message with no embedded relay-message option is
	// malformed: GetInnerMessage cannot decapsulate it, and the plugin must
	// drop the request rather than replying to a packet it cannot read.
	req := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayForward}
	stub, err := dhcpv6.NewMessage()
	require.NoError(t, err)

	resp, stop := h(req, stub)
	assert.Nil(t, resp)
	assert.True(t, stop)
}
