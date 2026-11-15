// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package requestlink

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestNewIDReturnsDistinctURLSafeValues(t *testing.T) {
	t.Parallel()

	a, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if a == b {
		t.Fatalf("two calls both returned %q, want distinct ids", a)
	}
	for _, id := range []string{a, b} {
		if _, err := base64.RawURLEncoding.DecodeString(id); err != nil {
			t.Errorf("id %q is not raw URL-safe base64: %v", id, err)
		}
	}
}

func TestOwnerAuthMatchesOnlyTheRightValue(t *testing.T) {
	t.Parallel()

	right := bytes.Repeat([]byte{1}, ownerAuthBytes)
	wrong := bytes.Repeat([]byte{2}, ownerAuthBytes)
	hash := hashOwnerAuth(right)

	if !ownerAuthMatches(right, hash) {
		t.Error("ownerAuthMatches(right, hash(right)) = false, want true")
	}
	if ownerAuthMatches(wrong, hash) {
		t.Error("ownerAuthMatches(wrong, hash(right)) = true, want false")
	}
}

func TestOwnerAuthMatchesRejectsAHashOfTheWrongLength(t *testing.T) {
	t.Parallel()

	value := bytes.Repeat([]byte{1}, ownerAuthBytes)
	if ownerAuthMatches(value, hashOwnerAuth(value)[:31]) {
		t.Error("ownerAuthMatches accepted a truncated stored hash")
	}
}

func TestSlotKeysAreDistinctPerLinkAndPerSlot(t *testing.T) {
	t.Parallel()

	if slotKey("a", 0) == slotKey("b", 0) {
		t.Error("slotKey collided across two different link ids")
	}
	if slotKey("a", 0) == slotKey("a", 1) {
		t.Error("slotKey collided across two different slots of the same link")
	}
	if slotKey("a", 0) == metadataKey("a") {
		t.Error("slotKey collided with metadataKey for the same link")
	}
}

func TestMetadataRoundTripsThroughJSON(t *testing.T) {
	t.Parallel()

	original := Metadata{
		MaxSubmissionBytes:       123,
		MaxConcurrentSubmissions: 4,
		OwnerAuthHash:            bytes.Repeat([]byte{9}, 32),
	}
	encoded, err := marshalMetadata(original)
	if err != nil {
		t.Fatalf("marshalMetadata: %v", err)
	}
	decoded, err := unmarshalMetadata(encoded)
	if err != nil {
		t.Fatalf("unmarshalMetadata: %v", err)
	}
	if decoded.MaxSubmissionBytes != original.MaxSubmissionBytes ||
		decoded.MaxConcurrentSubmissions != original.MaxConcurrentSubmissions ||
		!bytes.Equal(decoded.OwnerAuthHash, original.OwnerAuthHash) {
		t.Errorf("round trip = %+v, want %+v", decoded, original)
	}
}

func TestUnmarshalMetadataRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	if _, err := unmarshalMetadata([]byte("not json")); err == nil {
		t.Error("unmarshalMetadata(\"not json\") = nil error, want one")
	}
}
