// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package tui draws the server's activity in the terminal: the sockets it
// bound, each family's plugin chain, and what happened to every request.
//
// Observer methods run on the server's packet goroutines: they fold the event
// into the model under one mutex and return, because formatting there would
// make the packet path wait on tview's queue. A ticker draws the other way,
// rendering pure functions of one locked snapshot inside QueueUpdateDraw.
package tui
