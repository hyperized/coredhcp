// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// The coredhcp-docgen command renders every plugin's package doc to the
// README.md GitHub shows for that plugin's directory.
//
// Run it through `go generate ./plugins/` rather than by hand. With -check it
// writes nothing and fails when a README no longer matches its package doc,
// which is how CI catches a doc.go edited without regenerating.
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/coredhcp/coredhcp/cmd/coredhcp-docgen/internal/docgen"
)

func main() {
	log.SetFlags(0)
	root := flag.String("root", ".", "repository root, the directory holding go.mod and plugins/")
	check := flag.Bool("check", false, "write nothing and exit non-zero when a README differs from its package doc")
	flag.Parse()

	if err := run(*root, *check); err != nil {
		log.Fatal(err)
	}
}

func run(root string, check bool) error {
	readmes, err := docgen.Render(root)
	if err != nil {
		return err
	}
	if check {
		return report(readmes)
	}
	return docgen.Write(readmes)
}

// report names every README that drifted from its package doc, so the CI log
// says which file to look at instead of only that something is stale.
func report(readmes []docgen.README) error {
	stale, err := docgen.Differing(readmes)
	if err != nil {
		return err
	}
	if len(stale) == 0 {
		return nil
	}
	return fmt.Errorf("%d README(s) no longer match their package doc:\n\t%s\nrun 'go generate ./plugins/' and commit the result",
		len(stale), strings.Join(stale, "\n\t"))
}
