// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ipv6only

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup4(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		h, err := setup4()
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("valid duration", func(t *testing.T) {
		h, err := setup4("10s")
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("invalid duration", func(t *testing.T) {
		h, err := setup4("not-a-duration")
		assert.Nil(t, h)
		assert.ErrorContains(t, err, `"not-a-duration" is not a duration`)
	})

	t.Run("too many arguments", func(t *testing.T) {
		h, err := setup4("10s", "extra")
		assert.Nil(t, h)
		assert.ErrorContains(t, err, "ipv6only takes at most one")
	})

	t.Run("invalid duration takes precedence over too many arguments", func(t *testing.T) {
		h, err := setup4("not-a-duration", "extra")
		assert.Nil(t, h)
		assert.ErrorContains(t, err, `"not-a-duration" is not a duration`)
	})
}
