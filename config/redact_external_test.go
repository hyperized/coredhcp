// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/config"
)

func TestRedactArgs(t *testing.T) {
	testcases := []struct {
		name string
		args []string
		want []string
	}{
		{"nil input returns nil", nil, nil},
		{"empty slice returns empty slice", []string{}, []string{}},
		{"password prefix redacted", []string{"password:hunter2"}, []string{"password:***"}},
		{"token prefix redacted", []string{"token:abc123"}, []string{"token:***"}},
		{"secret prefix redacted", []string{"secret:xyz"}, []string{"secret:***"}},
		{"mixed case prefix redacted, casing kept", []string{"Token:abc123"}, []string{"Token:***"}},
		{"password env marker left alone", []string{"password:env:REDIS_PASSWORD"}, []string{"password:env:REDIS_PASSWORD"}},
		{"password env marker mixed case left alone", []string{"password:ENV:FOO"}, []string{"password:ENV:FOO"}},
		{"password with empty value redacted to the marker", []string{"password:"}, []string{"password:***"}},
		{"key prefix is not a secret", []string{"key:something"}, []string{"key:something"}},
		{
			"url with userinfo password redacted",
			[]string{"redis://user:hunter2@localhost:6379/0"},
			[]string{"redis://user:***@localhost:6379/0"},
		},
		{
			"url with user but no password left alone",
			[]string{"redis://user@localhost:6379/0"},
			[]string{"redis://user@localhost:6379/0"},
		},
		{
			"url with no userinfo left alone",
			[]string{"redis://localhost:6379/0"},
			[]string{"redis://localhost:6379/0"},
		},
		{
			"argument that fails url.Parse left alone",
			[]string{"http://a b.com/%zz"},
			[]string{"http://a b.com/%zz"},
		},
		{"plain argument left alone", []string{"255.255.255.0"}, []string{"255.255.255.0"}},
		{
			"multiple args each handled independently",
			[]string{"password:hunter2", "key:something", "redis://user:hunter2@localhost:6379/0"},
			[]string{"password:***", "key:something", "redis://user:***@localhost:6379/0"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.RedactArgs(tc.args)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRedactArgsDoesNotMutateInput(t *testing.T) {
	input := []string{"password:hunter2"}

	got := config.RedactArgs(input)

	require.Equal(t, []string{"password:***"}, got)
	assert.Equal(t, []string{"password:hunter2"}, input)
}
