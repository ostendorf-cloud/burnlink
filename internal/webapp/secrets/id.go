// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	// idBytes is the entropy of a secret id: 128 bits from crypto/rand. The
	// id is the only thing that protects a stored ciphertext from a guesser,
	// so it is never shorter than this.
	idBytes = 16
	// idLen is the length of the id's unpadded base64url form.
	idLen = 22

	// dummyID is a well formed id the service never issues: it is the
	// encoding of 16 zero bytes, and the chance NewID returns it is 2^-128.
	// A request with a malformed id is looked up under it, so malformed and
	// unknown ids both cost one store round trip.
	dummyID = "AAAAAAAAAAAAAAAAAAAAAA"
)

// idEncoding is strict, so a string that is not the canonical encoding of
// exactly one 16 byte value, such as one with stray trailing bits, is
// malformed instead of a second spelling of an existing id.
var idEncoding = base64.RawURLEncoding.Strict()

// NewID returns a fresh secret id: 16 random bytes, base64url without
// padding, 22 characters of [A-Za-z0-9_-].
func NewID() (string, error) {
	raw := make([]byte, idBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("secrets: generate id: %w", err)
	}
	return idEncoding.EncodeToString(raw), nil
}

// validID reports whether id is the canonical encoding of 16 bytes. It is the
// gate in front of the store: nothing else reaches a key.
func validID(id string) bool {
	if len(id) != idLen {
		return false
	}
	raw, err := idEncoding.DecodeString(id)
	return err == nil && len(raw) == idBytes
}
