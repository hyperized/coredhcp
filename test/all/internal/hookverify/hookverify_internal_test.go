// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package hookverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMac(t *testing.T) {
	t.Parallel()

	secret := "s3cret"
	body := []byte(`{"event":"lease4_commit"}`)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	want := h.Sum(nil)

	if got := mac(secret, body); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("mac(%q, %q) = %x, want %x", secret, body, got, want)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	const secret = "s3cret"
	body := []byte(`{"event":"lease4_commit"}`)
	validHeader := Sign(secret, body)

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{
			name:   "valid signature",
			header: validHeader,
			want:   true,
		},
		{
			name:   "missing prefix",
			header: hex.EncodeToString(mac(secret, body)),
			want:   false,
		},
		{
			name:   "not hex after the prefix",
			header: signaturePrefix + "not-hex",
			want:   false,
		},
		{
			name:   "right hex, wrong digest length",
			header: signaturePrefix + "aabb",
			want:   false,
		},
		{
			name:   "digest for a different secret",
			header: signaturePrefix + hex.EncodeToString(mac("other-secret", body)),
			want:   false,
		},
		{
			name:   "empty header",
			header: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Verify(secret, tt.header, body); got != tt.want {
				t.Errorf("Verify(%q, %q, body) = %v, want %v", secret, tt.header, got, tt.want)
			}
		})
	}
}
