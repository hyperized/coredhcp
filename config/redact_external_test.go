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
		{"token env marker left alone", []string{"token:env:NETBOX_TOKEN"}, []string{"token:env:NETBOX_TOKEN"}},
		// The plugins cut "env:" case-sensitively, so "ENV:FOO" is a literal
		// password to them and has to be redacted here.
		{"password env marker in the wrong case is a literal", []string{"password:ENV:FOO"}, []string{"password:***"}},
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
		// netbox takes its token as a bare positional argument, so these are
		// recognised by shape alone.
		{"bare netbox v2 token redacted", []string{"nbt_ABCdef123"}, []string{"***"}},
		{
			"bare legacy netbox token redacted",
			[]string{"0123456789abcdef0123456789abcdef01234567"},
			[]string{"***"},
		},
		{
			"bare legacy netbox token in upper case redacted",
			[]string{"0123456789ABCDEF0123456789ABCDEF01234567"},
			[]string{"***"},
		},
		{"netbox token behind a prefix keeps the prefix", []string{"token:nbt_ABCdef123"}, []string{"token:***"}},
		{
			"39 hex characters is not a token",
			[]string{"0123456789abcdef0123456789abcdef0123456"},
			[]string{"0123456789abcdef0123456789abcdef0123456"},
		},
		{
			"41 hex characters is not a token",
			[]string{"0123456789abcdef0123456789abcdef012345678"},
			[]string{"0123456789abcdef0123456789abcdef012345678"},
		},
		{
			"40 characters with a non-hex one is not a token",
			[]string{"z123456789abcdef0123456789abcdef01234567"},
			[]string{"z123456789abcdef0123456789abcdef01234567"},
		},
		{"nbt without the underscore is not a token", []string{"nbtree"}, []string{"nbtree"}},
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
