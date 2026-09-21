// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package hookverify checks the signature the leasehook plugin attaches to
// its webhook deliveries. The end-to-end test helper uses it to tell a
// correctly signed request from a forged or corrupted one; it does not act
// on the result itself, since the point of the helper is to record what it
// saw rather than to police it.
package hookverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// signaturePrefix marks the header value as a hex-encoded HMAC-SHA256, the
// only scheme the leasehook plugin writes.
const signaturePrefix = "sha256="

// Verify reports whether header is the signature leasehook writes for body
// under secret: the string "sha256=" followed by the hex HMAC-SHA256.
func Verify(secret, header string, body []byte) bool {
	encoded, ok := strings.CutPrefix(header, signaturePrefix)
	if !ok {
		return false
	}
	got, err := hex.DecodeString(encoded)
	if err != nil {
		return false
	}
	// ConstantTimeCompare itself returns 0 immediately on a length mismatch
	// rather than panicking, so a header with the wrong digest length is
	// simply rejected here.
	return subtle.ConstantTimeCompare(got, mac(secret, body)) == 1
}

// Sign returns the header value leasehook writes for body under secret.
func Sign(secret string, body []byte) string {
	return signaturePrefix + hex.EncodeToString(mac(secret, body))
}

// mac computes the HMAC-SHA256 of body under secret.
func mac(secret string, body []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return h.Sum(nil)
}
