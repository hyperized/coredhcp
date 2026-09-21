// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package hookverify_test

import (
	"testing"

	"github.com/coredhcp/coredhcp/test/all/internal/hookverify"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	const secret = "top-secret"
	body := []byte(`{"event":"lease4_commit","mac":"02:00:00:c0:de:31"}`)

	header := hookverify.Sign(secret, body)
	if !hookverify.Verify(secret, header, body) {
		t.Fatalf("Verify(%q, %q, body) = false, want true", secret, header)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	t.Parallel()

	const secret = "top-secret"
	header := hookverify.Sign(secret, []byte(`{"event":"lease4_commit"}`))
	tampered := []byte(`{"event":"lease4_release"}`)

	if hookverify.Verify(secret, header, tampered) {
		t.Fatal("Verify accepted a signature computed for a different body")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	body := []byte(`{"event":"lease4_commit"}`)
	header := hookverify.Sign("top-secret", body)

	if hookverify.Verify("wrong-secret", header, body) {
		t.Fatal("Verify accepted a signature made with a different secret")
	}
}

func TestSignIsDeterministic(t *testing.T) {
	t.Parallel()

	body := []byte(`{"event":"lease4_commit"}`)
	first := hookverify.Sign("top-secret", body)
	second := hookverify.Sign("top-secret", body)
	if first != second {
		t.Fatal("Sign produced two different headers for the same secret and body")
	}
}
