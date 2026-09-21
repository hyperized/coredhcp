// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package nbp implements handling of an NBP (Network Boot Program) using an
// URL, e.g. http://[fe80::abcd:efff:fe12:3456]/my-nbp or tftp://10.0.0.1/my-nbp .
// The NBP information is only added if it is requested by the client.
//
// Note that for DHCPv4, unless the URL is prefixed with a "http", "https" or
// "ftp" scheme, the URL will be split into TFTP server name (option 66)
// and Bootfile name (option 67), so the scheme will be stripped out, and it
// will be treated as a TFTP URL. Anything other than host name and file path
// will be ignored (no port, no query string, etc).
//
// For DHCPv6 OPT_BOOTFILE_URL (option 59) is used, and the value is passed
// unmodified. If the query string is specified and contains a "param" key,
// its value is also passed as OPT_BOOTFILE_PARAM (option 60), so it will be
// duplicated between option 59 and 60.
//
// Example usage:
//
// server6:
//   - plugins:
//   - nbp: http://[2001:db8:a::1]/nbp
//
// server4:
//   - plugins:
//   - nbp: tftp://10.0.0.254/nbp
//
// # Placement
//
// Every path through the plugin ends the handler chain, on both families and
// whether or not the client asked for a boot file, so nbp can only be the
// last plugin in a chain.
package nbp
