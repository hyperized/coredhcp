// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build !linux

package main

import "errors"

// openRawUDP needs an AF_PACKET socket, which only Linux has. The exerciser
// only ever runs in the compose stack's Linux containers; this stub is what
// keeps `go build ./...` working on the machine the code is written on.
func openRawUDP(_ string, _ int) (rawUDPConn, error) {
	return nil, errors.New("the on-link DHCPv4 client needs an AF_PACKET socket, which only Linux has; run the exerciser through `make test-all` rather than on this host")
}
