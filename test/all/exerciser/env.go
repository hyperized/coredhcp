// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// settings is the topology the compose file put in the environment: who the
// server is, who we are on each of the two bridges, and where the backends
// live. Everything the plugins were configured with is read from the
// server's own rendered configuration instead, see serverconf.
type settings struct {
	serverLAN4  netip.Addr
	serverRLY4  netip.Addr
	serverLAN6  netip.Addr
	serverRLY6  netip.Addr
	selfLAN4    netip.Addr
	selfRLY4    netip.Addr
	selfLAN6    netip.Addr
	selfRLY6    netip.Addr
	foreignRLY4 netip.Addr

	macFile      net.HardwareAddr
	macFile6     net.HardwareAddr
	macDenied    net.HardwareAddr
	macNetbox    net.HardwareAddr
	macNetbox404 net.HardwareAddr
	macRedis     net.HardwareAddr

	fileAddr4      netip.Addr
	fileAddr6      netip.Addr
	netboxAddr4    netip.Addr
	netboxAddr6    netip.Addr
	redisAddr4     netip.Addr
	redisAddr6     netip.Addr
	relayinfoAddr4 netip.Addr
	relayinfoAddr6 netip.Addr

	subnetPool4   addrRange
	subnetRouter4 netip.Addr
	subnetDNS6    netip.Addr

	circuitID   string
	interfaceID string

	configPath     string
	leaseAPISocket string
	metricsSocket  string
	helperURL      string
	knotAddr       string
	dnsZone        string
	resultsDir     string
	hookSecret     string

	timeout       time.Duration
	burstRequests int
}

// addrRange is an inclusive first-to-last address range, the way the range
// and subnet plugins write a pool.
type addrRange struct {
	first netip.Addr
	last  netip.Addr
}

// contains reports whether a is inside the range.
func (r addrRange) contains(a netip.Addr) bool {
	return r.first.IsValid() && a.IsValid() &&
		a.Compare(r.first) >= 0 && a.Compare(r.last) <= 0
}

func (r addrRange) String() string { return r.first.String() + "-" + r.last.String() }

// loader collects every environment problem before reporting, so a
// misconfigured stack names all of its mistakes in one run instead of one
// per restart.
type loader struct {
	problems []string
}

func (l *loader) fail(name, why string) {
	l.problems = append(l.problems, name+": "+why)
}

func (l *loader) str(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		l.fail(name, "is unset or empty; the compose file sets it, check test/all/docker-compose.yml")
	}
	return v
}

func (l *loader) addr(name string) netip.Addr {
	v := l.str(name)
	if v == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		l.fail(name, strconv.Quote(v)+" is not an IP address; write a literal such as 172.31.246.2")
		return netip.Addr{}
	}
	return a.Unmap()
}

func (l *loader) mac(name string) net.HardwareAddr {
	v := l.str(name)
	if v == "" {
		return nil
	}
	m, err := net.ParseMAC(v)
	if err != nil {
		l.fail(name, strconv.Quote(v)+" is not a MAC address; write six hex octets separated by colons")
		return nil
	}
	return m
}

func (l *loader) addrRange(name string) addrRange {
	v := l.str(name)
	if v == "" {
		return addrRange{}
	}
	first, last, ok := strings.Cut(v, "-")
	if !ok {
		l.fail(name, strconv.Quote(v)+" is not a range; write it as <first>-<last>")
		return addrRange{}
	}
	f, errF := netip.ParseAddr(first)
	t, errL := netip.ParseAddr(last)
	if errF != nil || errL != nil {
		l.fail(name, strconv.Quote(v)+" holds an address that does not parse; write it as <first>-<last>")
		return addrRange{}
	}
	return addrRange{first: f.Unmap(), last: t.Unmap()}
}

func (l *loader) duration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		l.fail(name, strconv.Quote(v)+" is not a positive duration; write it the Go way, such as 420s")
		return fallback
	}
	return d
}

func (l *loader) count(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		l.fail(name, strconv.Quote(v)+" is not a positive count")
		return fallback
	}
	return n
}

// loadSettings reads the whole topology out of the environment.
func loadSettings() (*settings, error) {
	l := &loader{}
	s := &settings{
		serverLAN4:  l.addr("SERVER_LAN4"),
		serverRLY4:  l.addr("SERVER_RELAY4"),
		serverLAN6:  l.addr("SERVER_LAN6"),
		serverRLY6:  l.addr("SERVER_RELAY6"),
		selfLAN4:    l.addr("SELF_LAN4"),
		selfRLY4:    l.addr("SELF_RELAY4"),
		selfLAN6:    l.addr("SELF_LAN6"),
		selfRLY6:    l.addr("SELF_RELAY6"),
		foreignRLY4: l.addr("FOREIGN_RELAY4"),

		macFile:      l.mac("MAC_FILE"),
		macFile6:     l.mac("MAC_FILE6"),
		macDenied:    l.mac("MAC_DENIED"),
		macNetbox:    l.mac("MAC_NETBOX"),
		macNetbox404: l.mac("MAC_NETBOX_NOTFOUND"),
		macRedis:     l.mac("MAC_REDIS"),

		fileAddr4:      l.addr("FILE_ADDR4"),
		fileAddr6:      l.addr("FILE_ADDR6"),
		netboxAddr4:    l.addr("NETBOX_ADDR4"),
		netboxAddr6:    l.addr("NETBOX_ADDR6"),
		redisAddr4:     l.addr("REDIS_ADDR4"),
		redisAddr6:     l.addr("REDIS_ADDR6"),
		relayinfoAddr4: l.addr("RELAYINFO_ADDR4"),
		relayinfoAddr6: l.addr("RELAYINFO_ADDR6"),

		subnetPool4:   l.addrRange("SUBNET_POOL4"),
		subnetRouter4: l.addr("SUBNET_ROUTER4"),
		subnetDNS6:    l.addr("SUBNET_DNS6"),

		circuitID:   l.str("CIRCUIT_ID"),
		interfaceID: l.str("INTERFACE_ID"),

		configPath:     l.str("CONFIG_PATH"),
		leaseAPISocket: l.str("LEASEAPI_SOCKET"),
		metricsSocket:  l.str("METRICS_SOCKET"),
		helperURL:      strings.TrimSuffix(l.str("HELPER_URL"), "/"),
		knotAddr:       l.str("KNOT_ADDR"),
		dnsZone:        l.str("DNS_ZONE"),
		resultsDir:     l.str("RESULTS_DIR"),
		hookSecret:     l.str("LEASEHOOK_SECRET"),

		timeout:       l.duration("EXERCISER_TIMEOUT", 420*time.Second),
		burstRequests: l.count("BURST_REQUESTS", 1200),
	}
	if len(l.problems) > 0 {
		return nil, fmt.Errorf("the environment is incomplete:\n  %s", strings.Join(l.problems, "\n  "))
	}
	return s, nil
}

// errNoInterface says the container does not look the way the compose file
// describes it.
var errNoInterface = errors.New("no interface carries that address")

// interfaceFor finds the interface holding addr. The exerciser is on two
// bridges and docker decides which is eth0, so every socket is opened
// against the interface that carries the address the compose file pinned
// rather than against a hard-coded name.
func interfaceFor(addr netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w; the container needs to see its own links", err)
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			if prefix.Addr().Unmap() == addr {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("%s: %w; check the ipv4_address and ipv6_address the compose file pins on this service", addr, errNoInterface)
}
