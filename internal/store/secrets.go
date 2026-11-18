// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrExists is returned by Secrets.Put when the id already holds a value.
// The existing value is untouched.
var ErrExists = errors.New("store: id already exists")

// ErrNotFound is returned by Secrets.Take when there is nothing to hand out.
// An id that expired, that was already taken and that never existed all
// produce this same error on purpose: the store keeps no record that could
// tell them apart, and the API must answer all three with one
// indistinguishable refusal. Never add a second sentinel for one cause.
var ErrNotFound = errors.New("store: not found")

// SecretKeyPrefix is put in front of every id Secrets stores. The store is
// shared with other features, such as internal/webapp/requestlink, whose keys
// start with "requestlink:". A secret id of "requestlink:abc:submission:0"
// is stored as "secret:requestlink:abc:submission:0" and reaches none of it.
const SecretKeyPrefix = "secret:"

// Backend is what Secrets needs from a store: the Store primitives plus a
// liveness probe. The Redis-compatible client in internal/store/redisstore
// is the production implementation.
type Backend interface {
	Store
	// Ping reports whether the store answers right now.
	Ping(ctx context.Context) error
}

// Secrets stores a ciphertext once and hands it out exactly once.
//
// It only speaks the two primitives the concept names: SET NX PX through
// Store.SetNX, and GETDEL through Store.GetDel. A secret expires through
// the store's own lifetime on the key; this service runs no sweeper.
//
// Secrets never looks inside a value and never limits its size. Rejecting an
// oversized ciphertext, validating an id and choosing the lifetime are the
// API layer's job. The API layer must still validate ids: the prefix keeps a
// secret id out of other features' keys, it does not make any id safe.
//
// Every key is SecretKeyPrefix plus the id. The request link keeps its data
// in the same store under "requestlink:", so the two keyspaces cannot meet,
// whatever id a caller passes.
type Secrets struct {
	backend Backend
}

// NewSecrets returns a Secrets over backend.
func NewSecrets(backend Backend) *Secrets {
	return &Secrets{backend: backend}
}

// Put stores ciphertext under id for ttl. The store enforces that an
// existing id is never overwritten, in the same operation as the write, so
// two concurrent writers cannot both win. It returns ErrExists when the id
// is taken. ttl must be positive: a secret without a lifetime is refused.
//
// A backend error does not say whether the write happened. If the store
// executed SET NX and only the reply was lost, a manual retry of the same
// write returns ErrExists for the caller's own earlier write. The caller
// should treat a failed Put as a failure to hand out the link, not retry it
// under the same id.
func (s *Secrets) Put(ctx context.Context, id string, ciphertext []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("store: put: ttl must be positive")
	}
	ok, err := s.backend.SetNX(ctx, SecretKeyPrefix+id, ciphertext, ttl)
	if err != nil {
		return fmt.Errorf("store: put: %w", err)
	}
	if !ok {
		return ErrExists
	}
	return nil
}

// Take returns the ciphertext stored under id and deletes it in one store
// operation, so of two concurrent readers at most one is served. It returns
// ErrNotFound when there is nothing to hand out, whatever the reason.
//
// A backend error does not say whether the secret was consumed. If the store
// executed GETDEL and the reply was lost, for example because a read timeout
// fired first, the secret is gone and the caller got an error. The client
// does not retry on its own, so a failure is visible. The caller reports a
// failure, not "not found".
func (s *Secrets) Take(ctx context.Context, id string) ([]byte, error) {
	value, ok, err := s.backend.GetDel(ctx, SecretKeyPrefix+id)
	if err != nil {
		return nil, fmt.Errorf("store: take: %w", err)
	}
	if !ok {
		return nil, ErrNotFound
	}
	return value, nil
}

// Exists reports whether a secret is stored under id, without taking it. It
// reads through Store.Get, the only non destructive read the contract has,
// so it transfers the value from the store and drops it; the check is cheap
// for a secret of the configured size limit and never consumes anything.
// Like Take, it cannot tell expired, taken and unknown apart.
func (s *Secrets) Exists(ctx context.Context, id string) (bool, error) {
	_, ok, err := s.backend.Get(ctx, SecretKeyPrefix+id)
	if err != nil {
		return false, fmt.Errorf("store: exists: %w", err)
	}
	return ok, nil
}

// Ping reports whether the store is reachable, for the readiness probe. Its
// error text can reach a log, so a Backend must keep credentials out of it.
func (s *Secrets) Ping(ctx context.Context) error {
	if err := s.backend.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}
