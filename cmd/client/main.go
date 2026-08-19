// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Sample DHCPv6 client to test on the local interface.
package main

import (
	"flag"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/coredhcp/coredhcp/logger"
)

var log = logger.GetLogger("main")

var flagInterface = flag.String("interface", "lo", "Interface to run the exchange on")

func main() {
	flag.Parse()

	macString := "00:11:22:33:44:55"
	if len(flag.Args()) > 0 {
		macString = flag.Arg(0)
	}

	if err := run(macString, *flagInterface); err != nil {
		log.Fatal(err)
	}
}

// run performs one solicit/advertise exchange as macString on the given
// interface. Split from main so it can be tested.
func run(macString, ifname string) error {
	c := client6.NewClient()
	c.LocalAddr = &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 546,
	}
	c.RemoteAddr = &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 547,
	}
	log.Printf("%+v", c)

	mac, err := net.ParseMAC(macString)
	if err != nil {
		return err
	}
	duid := dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          dhcpv6.GetTime(),
		LinkLayerAddr: mac,
	}

	conv, err := c.Exchange(ifname, dhcpv6.WithClientID(&duid))
	printConversation(conv)
	return err
}

// printConversation logs a summary of every message in the exchange.
func printConversation(conv []dhcpv6.DHCPv6) {
	for _, p := range conv {
		log.Print(p.Summary())
	}
}
