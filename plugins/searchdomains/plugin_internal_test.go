// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package searchdomains

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopySlice(t *testing.T) {
	cases := []struct {
		name     string
		original []string
	}{
		{name: "nil", original: nil},
		{name: "empty", original: []string{}},
		{name: "populated", original: []string{"domain.a", "domain.b"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := copySlice(tc.original)
			// copySlice always allocates via make(), so a nil input yields
			// an empty (non-nil) slice rather than nil; compare contents,
			// not identity.
			assert.Equal(t, len(tc.original), len(got))
			assert.ElementsMatch(t, tc.original, got)

			// The copy must be independent: mutating it must not affect the
			// original, so downstream plugins can't corrupt our state.
			if len(got) > 0 {
				got[0] = "mutated"
				assert.NotEqual(t, tc.original[0], got[0])
			}
		})
	}
}

func TestSetup6EmptyArgs(t *testing.T) {
	h, err := setup6()
	assert.NoError(t, err)
	assert.NotNil(t, h)
}

func TestSetup4EmptyArgs(t *testing.T) {
	h, err := setup4()
	assert.NoError(t, err)
	assert.NotNil(t, h)
}
