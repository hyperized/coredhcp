// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package tui

import (
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/coredhcp/coredhcp/events"
)

// handleKey runs on tview's event goroutine and only touches the model, so a
// key press costs one lock instead of a round trip through the draw loop.
func (u *UI) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	// Unconditional: a press either changed the model or is about to be drawn over.
	defer u.m.touch()

	if quitKey(ev) {
		u.Stop()

		return nil
	}

	// Swallowing every non-quit key is what makes "any key closes it" true.
	if u.m.helpOpen() {
		u.m.toggleHelp()

		return nil
	}

	if u.handleRune(ev) || u.handleScroll(ev) {
		return nil
	}

	return ev
}

// Ctrl-C is caught here rather than left to tview, so shutdown always runs in
// the same order.
func quitKey(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyCtrlC, tcell.KeyEsc:
		return true
	case tcell.KeyRune:
		return ev.Rune() == 'q' || ev.Rune() == 'Q'
	}

	return false
}

func (u *UI) handleRune(ev *tcell.EventKey) bool {
	if ev.Key() != tcell.KeyRune {
		return false
	}

	switch r := ev.Rune(); r {
	case 'p', 'P':
		u.m.togglePause()
	case 'c', 'C':
		u.m.clearStats()
	case '?':
		u.m.toggleHelp()
	case '1', '2', '3', '4':
		u.m.setFocus(paneID(r - '1'))
	default:
		return false
	}

	return true
}

func (u *UI) handleScroll(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyTab:
		u.m.cycleFocus(1)
	case tcell.KeyBacktab:
		u.m.cycleFocus(-1)
	case tcell.KeyUp:
		u.m.scrollBy(-1)
	case tcell.KeyDown:
		u.m.scrollBy(1)
	case tcell.KeyPgUp:
		u.m.scrollPage(-1)
	case tcell.KeyPgDn:
		u.m.scrollPage(1)
	case tcell.KeyHome:
		u.m.scrollTop()
	case tcell.KeyEnd:
		u.m.scrollBottom()
	default:
		return false
	}

	return true
}

func (m *model) touch() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dirty = true
}

func (m *model) helpOpen() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.help
}

func (m *model) toggleHelp() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.help = !m.help
	m.dirty = true
}

// Collection keeps running: the pane freezes on a copy so the rows cannot
// shift under the operator while they read them.
func (m *model) togglePause() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.paused = !m.paused
	m.frozen = nil

	if m.paused {
		m.frozen = m.traffic.items()
	}

	m.dirty = true
}

// The lease table and the log survive: clearing the screen is about the noise,
// not the record of what the server did.
func (m *model) clearStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.traffic.reset()
	m.frozen = nil
	m.counts = map[events.Family]*familyCounters{}
	m.reqRate.reset()
	m.errRate.reset()

	m.tot.requests, m.tot.dropped, m.tot.errors = 0, 0, 0
	m.tot.lastSoftErr, m.tot.lastSendErr = time.Time{}, time.Time{}

	for i := range m.panes {
		m.panes[i].offset = 0
		m.panes[i].follow = paneID(i).follows()
	}

	m.dirty = true
}

func (m *model) setFocus(id paneID) {
	if id < 0 || id >= paneCount {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.focus = id
	m.dirty = true
}

func (m *model) cycleFocus(delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.focus = paneID((int(m.focus) + delta + int(paneCount)) % int(paneCount))
	m.dirty = true
}

// delta is relative to where the last frame put the window. Following stops as
// soon as the operator leaves the bottom, and resumes when they come back.
func (m *model) scrollBy(delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := &m.panes[m.focus]
	v.offset = max(v.start+delta, 0)
	v.follow = m.focus.follows() && v.offset >= max(v.total-v.height, 0)
	m.dirty = true
}

func (m *model) scrollPage(dir int) {
	m.mu.Lock()
	height := max(m.panes[m.focus].height, 1)
	m.mu.Unlock()

	m.scrollBy(dir * height)
}

func (m *model) scrollTop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := &m.panes[m.focus]
	v.offset, v.follow = 0, false
	m.dirty = true
}

func (m *model) scrollBottom() {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := &m.panes[m.focus]
	v.offset = max(v.total-v.height, 0)
	v.follow = m.focus.follows()
	m.dirty = true
}
