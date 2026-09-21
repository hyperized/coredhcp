// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package file enables static mapping of client identifiers to IP addresses.
// The mapping is stored in a text file, where each mapping is described by one line containing
// two fields separated by whitespace: the client identifier and the IP address. For example:
//
//	$ cat leases_v4.txt
//	# IPv4 fixed addresses
//	00:11:22:33:44:55 10.0.0.1
//	a1:b2:c3:d4:e5:f6 10.0.10.10  # lowercase is permitted
//
//	$ cat leases_v6.txt
//	# IPv6 fixed addresses
//	00:11:22:33:44:55 2001:db8::10:1
//	A1:B2:C3:D4:E5:F6 2001:db8::10:2
//
// Any text following '#' is a comment that is ignored.
//
// MAC addresses can be upper or lower case. IPv6 addresses should use lowercase, as per RFC-5952.
//
// Each identifier or IP address should normally be unique within the file. Warnings will be
// logged for any duplicates.
//
// To specify the plugin configuration in the server6/server4 sections of the config file, just
// pass the leases file name as plugin argument, e.g.:
//
//	$ cat config.yml
//
//	server6:
//	   ...
//	   plugins:
//	     - file: "file_leases.txt" [autorefresh] [key:mac|duid|client-id]
//	   ...
//
// If the file path is not absolute, it is relative to the cwd where coredhcp is run.
//
// The two optional arguments may be given in either order. An argument that is neither of them
// fails setup by name, so a typo shows up at startup instead of being ignored.
//
// The keyword 'autorefresh' can be used as shown, or it can be omitted. When present, the plugin
// will try to refresh the lease mapping during runtime whenever the lease file is updated.
//
// # Lookup key
//
// The 'key:' argument says which identifier the first field of a lease line holds. It defaults
// to 'mac', the historical behaviour and the only mode both families accept.
//
// 'key:duid' is for server6 and fails setup under server4. A MAC address is a poor key there: a
// client identifying with a DUID-EN or a DUID-UUID carries no link-layer address in its DUID,
// and behind a relay that sends no client link-layer address option there is nothing to extract
// either. The first field is then the DUID as it goes on the wire, two-octet type code included,
// written in hexadecimal in either case, with an optional 0x prefix and optional colons between
// the bytes. These three lines name the same client:
//
//	0x00030001aabbccddeeff 2001:db8::10:1
//	00:03:00:01:aa:bb:cc:dd:ee:ff 2001:db8::10:1
//	00030001AABBCCDDEEFF 2001:db8::10:1
//
// A DUID is at most 130 octets, since RFC 8415 section 11.1 caps it at 128 and the type code is
// two more. A longer one is a setup error in the file, and a request carrying one is passed to
// the next plugin rather than looked up.
//
// 'key:client-id' is for server4 and fails setup under server6. It matches the raw bytes of
// option 61. RFC 2132 section 9.14 puts a type octet first: type 1 is a hardware address, so a
// client whose identifier is its MAC appears as 01 followed by the six address bytes, and an RFC
// 4361 client puts a DUID behind type 255. Everything else is opaque, and an identifier that
// reads as text can be written with a 'text:' prefix instead of as hexadecimal:
//
//	0x01aabbccddeeff 10.0.0.1
//	01:aa:bb:cc:dd:ee:ff 10.0.0.1
//	text:printer-2nd-floor 10.0.0.2
//
// A 'text:' value cannot contain whitespace, because lines are split on it. A client that sends
// no option 61 at all is passed to the next plugin.
//
// For DHCPv4 `server4`, note that the file plugin must come after any general plugins
// needed, e.g. dns or router. A DHCPv4 match ends the chain, which is what makes that
// ordering matter; DHCPv6 never ends it. The order is unimportant for DHCPv6, but will
// affect the order of options in the DHCPv6 response.
//
// The plugin does not act on RELEASE or DECLINE messages. Its mappings are static, so
// there is no lease to reclaim when a client gives one up or rejects one.
package file
