// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package config parses and validates the coredhcp server configuration.
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
	"github.com/spf13/viper"

	"github.com/coredhcp/coredhcp/logger"
)

var log = logger.GetLogger("config")

type protocolVersion int

const (
	protocolV6 protocolVersion = 6
	protocolV4 protocolVersion = 4
)

// Config holds the DHCPv6/v4 server configuration
type Config struct {
	v       *viper.Viper
	Server6 *ServerConfig
	Server4 *ServerConfig
}

// New returns a new initialized instance of a Config object
func New() *Config {
	return &Config{v: viper.New()}
}

// ServerConfig holds a server configuration that is specific to either the
// DHCPv6 server or the DHCPv4 server.
type ServerConfig struct {
	Addresses []net.UDPAddr
	Plugins   []PluginConfig
}

// PluginConfig holds the configuration of a plugin
type PluginConfig struct {
	Name string
	Args []string
}

// Load reads a configuration file and returns a Config object, or an error if
// any.
func Load(pathOverride string) (*Config, error) {
	log.Print("Loading configuration")
	c := New()
	c.v.SetConfigType("yml")
	if pathOverride != "" {
		c.v.SetConfigFile(pathOverride)
	} else {
		c.v.SetConfigName("config")
		c.v.AddConfigPath(".")
		c.v.AddConfigPath("$XDG_CONFIG_HOME/coredhcp/")
		c.v.AddConfigPath("$HOME/.coredhcp/")
		c.v.AddConfigPath("/etc/coredhcp/")
	}

	if err := c.v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err := c.parseConfig(protocolV6); err != nil {
		return nil, err
	}
	if err := c.parseConfig(protocolV4); err != nil {
		return nil, err
	}
	if c.Server6 == nil && c.Server4 == nil {
		return nil, ErrorFromString("need at least one valid config for DHCPv6 or DHCPv4")
	}
	return c, nil
}

func protoVersionCheck(v protocolVersion) error {
	if v != protocolV6 && v != protocolV4 {
		return fmt.Errorf("invalid protocol version: %d", v)
	}
	return nil
}

func parsePlugins(pluginList []interface{}) ([]PluginConfig, error) {
	plugins := make([]PluginConfig, 0, len(pluginList))
	for idx, val := range pluginList {
		conf := cast.ToStringMap(val)
		if conf == nil {
			return nil, ErrorFromString("dhcpv6: plugin #%d is not a string map", idx)
		}
		// make sure that only one item is specified, since it's a
		// map name -> args
		if len(conf) != 1 {
			return nil, ErrorFromString("dhcpv6: exactly one plugin per item can be specified")
		}
		var (
			name string
			args []string
		)
		// only one item, as enforced above, so read just that
		for k, v := range conf {
			name = k
			args = strings.Fields(cast.ToString(v))
			break
		}
		plugins = append(plugins, PluginConfig{Name: name, Args: args})
	}
	return plugins, nil
}

// BUG(Natolumin): listen specifications of the form `[ip6]%iface:port` or
// `[ip6]%iface` are not supported, even though they are the default format of
// the `ss` utility in linux. Use `[ip6%iface]:port` instead

// splitHostPort splits an address of the form ip%zone:port into ip,zone and port.
// It still returns if any of these are unset (unlike net.SplitHostPort which
// returns an error if there is no port)
func splitHostPort(hostport string) (ip string, zone string, port string, err error) {
	ip, port, err = net.SplitHostPort(hostport)
	if err != nil {
		// Either there is no port, or a more serious error.
		// Supply a synthetic port to differentiate cases
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

func (c *Config) getPlugins(ver protocolVersion) ([]PluginConfig, error) {
	if err := protoVersionCheck(ver); err != nil {
		return nil, err
	}
	pluginList := cast.ToSlice(c.v.Get(fmt.Sprintf("server%d.plugins", ver)))
	if pluginList == nil {
		return nil, ErrorFromString("dhcpv%d: invalid plugins section, not a list or no plugin specified", ver)
	}
	return parsePlugins(pluginList)
}

func (c *Config) parseConfig(ver protocolVersion) error {
	if err := protoVersionCheck(ver); err != nil {
		return err
	}
	if exists := c.v.Get(fmt.Sprintf("server%d", ver)); exists == nil {
		// it is valid to have no server configuration defined
		return nil
	}
	// read plugin configuration
	plugins, err := c.getPlugins(ver)
	if err != nil {
		return err
	}
	for _, p := range plugins {
		log.Printf("DHCPv%d: found plugin `%s` with %d args: %v", ver, p.Name, len(p.Args), p.Args)
	}

	listeners, err := c.parseListen(ver)
	if err != nil {
		return err
	}

	sc := ServerConfig{
		Addresses: listeners,
		Plugins:   plugins,
	}
	switch ver {
	case protocolV6:
		c.Server6 = &sc
	case protocolV4:
		c.Server4 = &sc
	}
	return nil
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
		l = append(l,
			net.UDPAddr{IP: dhcpv6.AllDHCPServers, Port: dhcpv6.DefaultServerPort},
			// XXX: Do we want to listen on [::] as default ?
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

	// Provide an emulation of the old keyword "interface" to avoid breaking config files
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
			// link-local multicast specified without interface gets expanded to listen on all interfaces
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

// defaultIP returns the unspecified address for the protocol version. The
// version has been validated by the caller; anything else is a programming
// error.
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

// defaultPort returns the standard server port for the protocol version. The
// version has been validated by the caller; anything else is a programming
// error.
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
