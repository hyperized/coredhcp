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
