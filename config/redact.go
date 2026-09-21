// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Redaction of plugin arguments for the startup log and for observers. A
// plugin takes its configuration as bare strings, and some of those strings
// are secrets: written inline as `password:hunter2`, named alongside a
// non-secret key as in ddns's `key:<name>:<base64 secret>`, buried in the
// userinfo of a connection URL, or, in the netbox plugin's original argument
// order, a bare positional API token with nothing around it to say what it is.
//
// What this file does is recognise the known shapes. It is a heuristic and
// cannot be anything else, so a secret in a shape nobody anticipated still
// reaches the log. env:NAME remains the form to reach for.

package config

import (
	"encoding/hex"
	"net/url"
	"strings"
)

// secretPrefixes are argument prefixes whose value is a secret to redact,
// matched case-insensitively. "key:" is handled separately by redactKey,
// because for that one prefix only part of the value is the secret.
var secretPrefixes = []string{"password:", "token:", "secret:"}

// keyPrefix marks the ddns plugin's TSIG argument, key:<name>:<secret>. See
// applyKey in plugins/ddns/plugin.go for the parse this has to mirror.
const keyPrefix = "key:"

// redacted is what replaces a secret. Short enough not to disturb a log line,
// and obviously not a value anyone configured.
const redacted = "***"

// NetBox tokens are matched by shape because the netbox plugin takes its
// token as a bare positional argument, so there is no prefix to key on. A v2
// token (NetBox 4.5 and later) starts with "nbt_"; a legacy one is 40
// hexadecimal characters, which is specific enough that no plugin argument in
// this tree collides with it.
const (
	netboxTokenPrefix = "nbt_"
	netboxTokenLen    = 40
)

// RedactArgs returns a copy of args with secret values replaced by ***. The
// input is never mutated: a nil slice stays nil, and every other case
// returns a freshly allocated slice and strings, even when nothing needed
// to change.
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

// redactArg applies the prefix rules first because they match on the
// argument's own syntax, and falls back to reading the argument as a URL
// only when none of them matched.
func redactArg(arg string) string {
	if r, ok := redactPrefixed(arg); ok {
		return r
	}
	if r, ok := redactKey(arg); ok {
		return r
	}
	if looksLikeNetboxToken(arg) {
		return redacted
	}
	return redactURL(arg)
}

// looksLikeNetboxToken reports whether arg has the shape of a NetBox API
// token. Nothing else in the argument carries that meaning: netbox reads the
// token from a fixed position, so redaction has to guess from the value.
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

// redactPrefixed handles the "password:", "token:" and "secret:" forms. A
// value written as "env:SOME_VAR" is left alone on purpose: it names an
// environment variable for the operator to read, not the secret itself. That
// marker is matched case-sensitively, the way the plugins parse it, so
// "password:ENV:FOO" is redacted here and treated as a literal password
// there.
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

// redactKey handles the ddns plugin's TSIG argument, key:<name>:<secret>.
// Only what follows the key name is secret, and "key:<name>:env:VAR" names an
// environment variable rather than carrying one, matched case-sensitively
// because applyKey reads it that way.
func redactKey(arg string) (string, bool) {
	lower := strings.ToLower(arg)
	if !strings.HasPrefix(lower, keyPrefix) {
		return "", false
	}
	name, secret, ok := strings.Cut(arg[len(keyPrefix):], ":")
	if !ok || strings.HasPrefix(secret, "env:") {
		return arg, true
	}
	return arg[:len(keyPrefix)] + name + ":" + redacted, true
}

// redactURL rewrites the password in a URL's userinfo, if it has one. An
// argument that does not parse as a URL is passed through rather than
// guessed at: most plugin arguments are addresses, prefixes or file paths
// and were never URLs to begin with.
func redactURL(arg string) string {
	u, err := url.Parse(arg)
	if err != nil || u.User == nil {
		return arg
	}
	if _, ok := u.User.Password(); !ok {
		return arg
	}
	u.User = url.UserPassword(u.User.Username(), redacted)
	// url.URL.String percent-encodes '*' in userinfo even though RFC 3986
	// section 3.2.1 allows it there unescaped, so the placeholder comes back
	// as %2A%2A%2A. Undo that one occurrence: the userinfo precedes the path
	// and the query, so the first match in the string is always ours.
	return strings.Replace(u.String(), "%2A%2A%2A", redacted, 1)
}
