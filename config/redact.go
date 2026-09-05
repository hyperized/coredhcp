// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Redaction of plugin arguments for the startup log and for observers. It
// recognises the known secret shapes and can never be more than a heuristic,
// so a secret written in an unanticipated shape still reaches the log:
// env:NAME remains the form to reach for.

package config

import (
	"encoding/hex"
	"net/url"
	"strings"
)

// Matched case-insensitively. "key:" is deliberately absent: it names a
// non-secret key rather than carrying one.
var secretPrefixes = []string{"password:", "token:", "secret:"}

const redacted = "***"

// The netbox plugin takes its token positionally, so there is no prefix to
// key on: v2 tokens start with "nbt_", legacy ones are 40 hex characters.
const (
	netboxTokenPrefix = "nbt_"
	netboxTokenLen    = 40
)

// RedactArgs returns a copy of args with secret values replaced by ***.
// args is never mutated, and a nil slice stays nil.
func RedactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = redactArg(a)
	}
	return out
}

// Order matters: the prefix rule reads the argument's own syntax, so it runs
// ahead of the shape guess and the URL parse, which both guess.
func redactArg(arg string) string {
	if r, ok := redactPrefixed(arg); ok {
		return r
	}
	if looksLikeNetboxToken(arg) {
		return redacted
	}
	return redactURL(arg)
}

func looksLikeNetboxToken(arg string) bool {
	if strings.HasPrefix(arg, netboxTokenPrefix) {
		return true
	}
	if len(arg) != netboxTokenLen {
		return false
	}
	_, err := hex.DecodeString(arg)
	return err == nil
}

// "env:NAME" is left alone: it names a variable, not the secret. Matched
// case-sensitively as the plugins do, so "password:ENV:FOO" is redacted.
func redactPrefixed(arg string) (string, bool) {
	lower := strings.ToLower(arg)
	for _, prefix := range secretPrefixes {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		value := arg[len(prefix):]
		if strings.HasPrefix(value, "env:") {
			return arg, true
		}
		return arg[:len(prefix)] + redacted, true
	}
	return "", false
}

// An argument that does not parse as a URL is passed through: most plugin
// arguments are addresses, prefixes or file paths and never were URLs.
func redactURL(arg string) string {
	u, err := url.Parse(arg)
	if err != nil || u.User == nil {
		return arg
	}
	if _, ok := u.User.Password(); !ok {
		return arg
	}
	u.User = url.UserPassword(u.User.Username(), redacted)
	// url.URL.String escapes '*' in userinfo though RFC 3986 section 3.2.1
	// allows it. Userinfo precedes path and query, so the first match is ours.
	return strings.Replace(u.String(), "%2A%2A%2A", redacted, 1)
}
