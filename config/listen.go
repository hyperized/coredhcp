// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/spf13/cast"
)

// splitHostPort splits ip%zone:port, tolerating what net.SplitHostPort
// rejects: a missing port, and the `[ip6]%iface:port` form ss prints.
func splitHostPort(hostport string) (ip string, zone string, port string, err error) {
	if i := strings.Index(hostport, "]%"); i >= 0 {
		rest := hostport[i+2:]
		zonePart, portPart := rest, ""
		if j := strings.IndexByte(rest, ':'); j >= 0 {
			zonePart, portPart = rest[:j], rest[j:]
		}
		hostport = hostport[:i] + "%" + zonePart + "]" + portPart
	}
	ip, port, err = net.SplitHostPort(hostport)
	if err != nil {
		// Retry with a synthetic port to tell "no port" from a syntax error.
		var altErr error
		if ip, _, altErr = net.SplitHostPort(hostport + ":0"); altErr != nil {
			// Invalid even with a fake port. Return the original error
			return
		}
		err = nil
	}
	if i := strings.LastIndexByte(ip, '%'); i >= 0 {
		ip, zone = ip[:i], ip[i+1:]
	}
	return
}

func (c *Config) getListenAddress(addr string, ver protocolVersion) (*net.UDPAddr, error) {
	if err := protoVersionCheck(ver); err != nil {
		return nil, err
	}

	ipStr, ifname, portStr, err := splitHostPort(addr)
	if err != nil {
		return nil, ErrorFromString("dhcpv%d: %v", ver, err)
	}

	ip := net.ParseIP(ipStr)
	if ipStr == "" {
		ip = defaultIP(ver)
	}
	if ip == nil {
		return nil, ErrorFromString("dhcpv%d: invalid IP address in `listen` directive: %s", ver, ipStr)
	}
	if ip4 := ip.To4(); (ver == protocolV6 && ip4 != nil) || (ver == protocolV4 && ip4 == nil) {
		return nil, ErrorFromString("dhcpv%d: not a valid IPv%d address in `listen` directive: '%s'", ver, ver, ipStr)
	}

	var port int
	if portStr == "" {
		port = defaultPort(ver)
	} else {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, ErrorFromString("dhcpv%d: invalid `listen` port '%s'", ver, portStr)
		}
	}

	listener := net.UDPAddr{
		IP:   ip,
		Port: port,
		Zone: ifname,
	}
	return &listener, nil
}

// BUG(Natolumin): When listening on link-local multicast addresses without
// binding to a specific interface, new interfaces coming up after the server
// starts will not be taken into account.

func expandLLMulticast(addr *net.UDPAddr) ([]net.UDPAddr, error) {
	if !addr.IP.IsLinkLocalMulticast() && !addr.IP.IsInterfaceLocalMulticast() {
		return nil, errors.New("address is not multicast")
	}
	if addr.Zone != "" {
		return nil, errors.New("address is already zoned")
	}
	var needFlags = net.FlagMulticast
	if addr.IP.To4() != nil {
		// We need to be able to send broadcast responses in ipv4
		needFlags |= net.FlagBroadcast
	}

	ifs, err := netInterfaces()
	ret := make([]net.UDPAddr, 0, len(ifs))
	if err != nil {
		return nil, fmt.Errorf("could not list network interfaces: %w", err)
	}
	for _, iface := range ifs {
		if (iface.Flags & needFlags) != needFlags {
			continue
		}
		caddr := *addr
		caddr.Zone = iface.Name
		ret = append(ret, caddr)
	}
	if len(ret) == 0 {
		return nil, errors.New("no suitable interface found for multicast listener")
	}
	return ret, nil
}

func defaultListen(ver protocolVersion) ([]net.UDPAddr, error) {
	switch ver {
	case protocolV4:
		return []net.UDPAddr{{Port: dhcpv4.ServerPort}}, nil
	case protocolV6:
		l, err := expandLLMulticast(&net.UDPAddr{IP: dhcpv6.AllDHCPRelayAgentsAndServers, Port: dhcpv6.DefaultServerPort})
		if err != nil {
			return nil, err
		}
		// No wildcard [::] listener on purpose: the multicast groups cover
		// clients and relays, and unicast everywhere has to be asked for.
		l = append(l,
			net.UDPAddr{IP: dhcpv6.AllDHCPServers, Port: dhcpv6.DefaultServerPort},
		)
		return l, nil
	}
	return nil, errors.New("defaultListen: Incorrect protocol version")
}

func (c *Config) parseListen(ver protocolVersion) ([]net.UDPAddr, error) {
	if err := protoVersionCheck(ver); err != nil {
		return nil, err
	}

	listen := c.v.Get(fmt.Sprintf("server%d.listen", ver))

	// "interface" is a deprecated alias for "listen", kept for old config files.
	if iface := c.v.Get(fmt.Sprintf("server%d.interface", ver)); iface != nil && listen != nil {
		return nil, ErrorFromString("interface is a deprecated alias for listen, " +
			"both cannot be used at the same time. Choose one and remove the other.")
	} else if iface != nil {
		listen = "%" + cast.ToString(iface)
	}

	if listen == nil {
		return defaultListen(ver)
	}

	addrs, err := cast.ToStringSliceE(listen)
	if err != nil {
		addrs = []string{cast.ToString(listen)}
	}

	listeners := []net.UDPAddr{}
	for _, a := range addrs {
		l, err := c.getListenAddress(a, ver)
		if err != nil {
			return nil, err
		}

		if l.Zone == "" && (l.IP.IsLinkLocalMulticast() || l.IP.IsInterfaceLocalMulticast()) {
			expanded, err := expandLLMulticast(l)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, expanded...)
			continue
		}

		listeners = append(listeners, *l)
	}
	return listeners, nil
}

// netInterfaces is swappable so interface-dependent listen expansion can be
// tested deterministically.
var netInterfaces = net.Interfaces

func defaultIP(ver protocolVersion) net.IP {
	switch ver {
	case protocolV4:
		return net.IPv4zero
	case protocolV6:
		return net.IPv6unspecified
	default:
		panic("BUG: Unknown protocol version")
	}
}

func defaultPort(ver protocolVersion) int {
	switch ver {
	case protocolV4:
		return dhcpv4.ServerPort
	case protocolV6:
		return dhcpv6.DefaultServerPort
	default:
		panic("BUG: Unknown protocol version")
	}
}
