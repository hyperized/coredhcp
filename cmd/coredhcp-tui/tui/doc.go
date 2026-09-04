// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package tui draws the server's activity in the terminal: which sockets it
// bound, which plugins are in each family's chain, and what happened to every
// request that came in.
//
// The package is an events.Observer. The server calls Request from the
// goroutine that handles the packet, so the observer methods do the least
// work they can get away with: take one mutex, fold the event into the model,
// mark it dirty, return. Nothing formats a string and nothing touches tview
// there, because tview's queue makes the caller wait for the draw loop.
//
// Everything the operator sees is derived from that model in the opposite
// direction: a ticker takes a snapshot under one lock, renders each pane from
// the snapshot plus the pane's own width and height, and hands the finished
// text to tview inside QueueUpdateDraw. The render functions are ordinary
// functions over a snapshot, so they can be tested without a screen; the
// tests that do want a screen use tcell's simulation screen.
package tui
