// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leases

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ResetRegistry empties the registry, immediately and again when the test
// finishes.
//
// It is exported from a _test.go file rather than from leases.go because
// shipped code has no business emptying the registry: plugins register once at
// startup and stay registered for the life of the process. The black-box test
// package needs it to keep cases independent of each other.
func ResetRegistry(t *testing.T) {
	t.Helper()
	resetRegistry()
	t.Cleanup(resetRegistry)
}

func resetRegistry() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.sources = nil
}

// stub is a Source that reports whatever it was built with.
type stub struct {
	name   string
	leases []Lease
	pools  []Pool
}

func (s *stub) Name() string    { return s.name }
func (s *stub) Leases() []Lease { return s.leases }
func (s *stub) Pools() []Pool   { return s.pools }

func TestRegisterKeepsOrder(t *testing.T) {
	ResetRegistry(t)

	first := &stub{name: "range a"}
	second := &stub{name: "range b"}
	Register(first)
	Register(second)

	require.Len(t, registry.sources, 2)
	assert.Same(t, first, registry.sources[0])
	assert.Same(t, second, registry.sources[1])
}

func TestRegisterIgnoresNil(t *testing.T) {
	ResetRegistry(t)

	Register(nil)

	assert.Empty(t, registry.sources)
}

func TestRegisterAcceptsDuplicateNames(t *testing.T) {
	ResetRegistry(t)

	// Two range plugins on one lease file report the same name and hold
	// different leases. Neither may shadow the other.
	Register(&stub{name: "range leases.sqlite3"})
	Register(&stub{name: "range leases.sqlite3"})

	assert.Len(t, registry.sources, 2)
}

func TestUnregister(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remove   func(a, b Source) Source
		wantLeft []string
	}{
		{
			name:     "first",
			remove:   func(a, _ Source) Source { return a },
			wantLeft: []string{"b"},
		},
		{
			name:     "last",
			remove:   func(_, b Source) Source { return b },
			wantLeft: []string{"a"},
		},
		{
			name:     "never registered",
			remove:   func(_, _ Source) Source { return &stub{name: "c"} },
			wantLeft: []string{"a", "b"},
		},
		{
			name:     "nil",
			remove:   func(_, _ Source) Source { return nil },
			wantLeft: []string{"a", "b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetRegistry(t)
			a, b := &stub{name: "a"}, &stub{name: "b"}
			Register(a)
			Register(b)

			Unregister(tc.remove(a, b))

			left := make([]string, 0, len(registry.sources))
			for _, s := range registry.sources {
				left = append(left, s.Name())
			}
			assert.Equal(t, tc.wantLeft, left)
		})
	}
}

func TestUnregisterRemovesOneRegistration(t *testing.T) {
	ResetRegistry(t)

	// A source registered twice is two entries, and one Unregister drops one
	// of them. Nothing does this on purpose; the point is that Unregister
	// does not quietly clear a name.
	s := &stub{name: "range a"}
	Register(s)
	Register(s)

	Unregister(s)

	assert.Len(t, registry.sources, 1)
}
