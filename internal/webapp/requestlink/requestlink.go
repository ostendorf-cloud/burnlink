// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package requestlink serves the reverse flow docs/concepts/burnlink.md and
// docs/adr/0003-request-link-key-material.md describe: an owner publishes a
// link, a stranger submits a secret back through it, and only the owner can
// open what arrives.
//
// The server never sees any key material, exactly as the send flow. It
// stores and serves ciphertext it cannot decrypt, through store.Store, plus
// the small amount of new, non-secret state a request link needs to enforce
// its own limits: see Metadata.
package requestlink

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// DefaultLifetime is how long a request link accepts submissions after
	// it is created. A placeholder default, like internal/config's other
	// unconfigured settings: it becomes a configured value once a later
	// milestone gives this service a reason to vary it.
	DefaultLifetime = 7 * 24 * time.Hour
	// DefaultMaxSubmissionBytes is the largest sealed payload a submission
	// endpoint accepts. A placeholder default; see DefaultLifetime.
	DefaultMaxSubmissionBytes = 1 << 20 // 1 MiB
	// DefaultMaxConcurrentSubmissions is how many submissions one request
	// link holds waiting at once before it refuses new ones, not a
	// lifetime total: opening the link frees every slot it holds back up,
	// so a submission arriving after that reuses one. A placeholder
	// default; see DefaultLifetime.
	DefaultMaxConcurrentSubmissions = 50
	// DefaultSubmitBurst is how many submissions one resolved client address
	// may make to one request link before DefaultSubmitPer starts refilling
	// its budget. A placeholder default; see DefaultLifetime.
	DefaultSubmitBurst = 1
	// DefaultSubmitPer is the refill period DefaultSubmitBurst spends over.
	// A placeholder default; see DefaultLifetime.
	DefaultSubmitPer = 10 * time.Second

	// DefaultLookupBurst is how many open or info calls one resolved client
	// address may make to one request link before DefaultLookupPer starts
	// refilling its budget. Larger than DefaultSubmitBurst: an owner checking
	// again by hand is expected, a stranger flooding submissions is not. A
	// placeholder default; see DefaultLifetime.
	DefaultLookupBurst = 10
	// DefaultLookupPer is the refill period DefaultLookupBurst spends over.
	DefaultLookupPer = 6 * time.Second
	// DefaultCreateBurst is how many request links one resolved client
	// address may create before DefaultCreatePer starts refilling its
	// budget. A placeholder default; see DefaultLifetime.
	DefaultCreateBurst = 5
	// DefaultCreatePer is the refill period DefaultCreateBurst spends over.
	DefaultCreatePer = time.Minute

	// idBytes is how many random bytes a request link's id carries, before
	// base64url encoding.
	idBytes = 16
	// ownerAuthBytes is the expected length of the owner auth value a
	// client derives from its private key. It is never stored; only its
	// SHA-256 digest is.
	ownerAuthBytes = 32
)

// Metadata is everything a request link carries about itself, read on every
// submission and every owner visit, never on the critical path for the
// submission content itself. Its JSON encoding is the value stored under
// the key metadataKey(id) builds; see store.Store's own doc comment for why
// that read has to be non-destructive.
//
// There is deliberately no owner public key in here: docs/adr/0003 settles
// that the server is never given it, so there is nothing here to leak it.
type Metadata struct {
	// ExpiresAt is when this request link stops accepting submissions and
	// stops answering owner visits. It is checked independently of the
	// store's own TTL, which only bounds how long the key survives, not
	// what a handler is willing to treat as still current.
	ExpiresAt time.Time `json:"expiresAt"`
	// MaxSubmissionBytes is the largest sealed payload accepted.
	MaxSubmissionBytes int `json:"maxSubmissionBytes"`
	// MaxConcurrentSubmissions is how many submissions this link holds
	// waiting at once, and the number of submission slots reserved for it;
	// see slotKey. It is not a lifetime total: an owner's open call frees
	// every slot it reads back up, so the link can go on accepting new
	// submissions for as long as it has not expired, however many it has
	// already handed out in total.
	MaxConcurrentSubmissions int `json:"maxConcurrentSubmissions"`
	// OwnerAuthHash is SHA-256 of the owner auth value the owner's browser
	// derives from its private key (docs/adr/0003's non-extractable
	// CryptoKey) and the matching public key, never the value itself. Only
	// whoever holds the private key can reproduce it, which is what tells
	// the open endpoint apart from the submit endpoint: both are reachable
	// by anyone holding the id, but only the owner's browser can pass this
	// check.
	OwnerAuthHash []byte `json:"ownerAuthHash"`
}

// NewID returns a random, URL-safe request link id.
func NewID() (string, error) {
	raw := make([]byte, idBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("requestlink: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// hashOwnerAuth returns the digest Metadata.OwnerAuthHash stores.
func hashOwnerAuth(ownerAuth []byte) []byte {
	sum := sha256.Sum256(ownerAuth)
	return sum[:]
}

// ownerAuthMatches reports whether ownerAuth hashes to want, in constant
// time: this is the one place a wrong guess and a right one must take the
// same time to reject or accept.
func ownerAuthMatches(ownerAuth, want []byte) bool {
	got := hashOwnerAuth(ownerAuth)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func metadataKey(id string) string {
	return "requestlink:" + id
}

// slotKey is one of MaxConcurrentSubmissions reserved slots a submission
// can claim. Enumerating slot 0..MaxConcurrentSubmissions-1 is also how the
// open endpoint finds every submission waiting, without the store offering
// a way to list keys: see Handler.Open.
func slotKey(id string, slot int) string {
	return fmt.Sprintf("requestlink:%s:submission:%d", id, slot)
}

func marshalMetadata(m Metadata) ([]byte, error) {
	return json.Marshal(m)
}

func unmarshalMetadata(raw []byte) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return Metadata{}, fmt.Errorf("requestlink: decode metadata: %w", err)
	}
	return m, nil
}
