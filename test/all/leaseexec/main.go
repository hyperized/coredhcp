// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Command leaseexec is the exec target the leasehook plugin's end-to-end
// test points at. Each run appends one line to a result file recording what
// reached it: the environment leasehook built and the event body on stdin.
//
// The output path is a constant, not a flag or an environment variable, on
// purpose: leasehook execs its target with an environment built from
// scratch (PATH, HOME, TMPDIR, LANG, LC_* and the LEASEHOOK_* variables, see
// plugins/leasehook's package doc) that carries nothing else the server
// holds, so there is no variable left for a path to travel in.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// outputPath is where every invocation appends its result line.
const outputPath = "/results/exec-hook.jsonl"

// maxStdin bounds how much of the event JSON is read.
const maxStdin = 1 << 20

// result is one line of the output file.
type result struct {
	Event     string          `json:"event"`
	Family    string          `json:"family"`
	MAC       string          `json:"mac"`
	Addresses string          `json:"addresses"`
	Hostname  string          `json:"hostname"`
	Body      json.RawMessage `json:"body,omitempty"`
	BodyError string          `json:"body_error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "leaseexec: %v; check %s exists and is writable\n", err, outputPath)
		os.Exit(1)
	}
}

func run() error {
	stdin, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdin))
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	res := result{
		Event:     os.Getenv("LEASEHOOK_EVENT"),
		Family:    os.Getenv("LEASEHOOK_FAMILY"),
		MAC:       os.Getenv("LEASEHOOK_MAC"),
		Addresses: os.Getenv("LEASEHOOK_ADDRESSES"),
		Hostname:  os.Getenv("LEASEHOOK_HOSTNAME"),
	}
	setBody(&res, stdin)

	line, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("encoding the result line: %w", err)
	}
	line = append(line, '\n')

	// #nosec G302,G306 -- 0o644 keeps the file readable by whatever collects
	// results after this program exits.
	f, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", outputPath, err)
	}
	defer func() { _ = f.Close() }()

	// A single Write of a buffer that already ends in a newline, so two
	// concurrent runs never interleave halves of a line in the shared file.
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("writing to %s: %w", outputPath, err)
	}
	return nil
}

// setBody attaches stdin to res as parsed JSON when it parses, or records
// why not: a malformed event should show up in the results, not vanish.
func setBody(res *result, stdin []byte) {
	stdin = bytes.TrimSpace(stdin)
	switch {
	case len(stdin) == 0:
		res.BodyError = "stdin was empty"
	case !json.Valid(stdin):
		res.BodyError = "stdin did not parse as JSON"
	default:
		res.Body = json.RawMessage(stdin)
	}
}
