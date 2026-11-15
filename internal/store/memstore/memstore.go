// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package memstore is an in-process store.Store, for tests and for a
// handler test suite that has no Redis-compatible server to talk to.
//
// It is not a production store: a value lives only in this process's
// memory, so it does not survive a restart and is not shared between
// replicas. burnlink's Helm chart allows more than one replica because
// today's scaffold keeps no server-side state at all; wiring this type into
// cmd/burnlink would quietly break that assumption. The real client issue #4
// adds is what belongs there.
package memstore

import (
	"context"
	"errors"
	"sync"
	"time"
)

// entry is one stored value with the time it stops being readable.
type entry struct {
	value     []byte
	expiresAt time.Time
}

// Store is an in-process, mutex-guarded store.Store. The zero value is not
// usable; build one with New.
type Store struct {
	// Now returns the current time. It defaults to time.Now and exists so
	// tests can control the clock.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]entry
}

// New returns an empty Store.
func New() *Store {
	return &Store{Now: time.Now, entries: make(map[string]entry)}
}

func (s *Store) clock() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// SetNX implements store.Store.
func (s *Store) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, errors.New("memstore: ttl must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()
	if e, ok := s.entries[key]; ok && now.Before(e.expiresAt) {
		return false, nil
	}
	s.entries[key] = entry{value: cloneBytes(value), expiresAt: now.Add(ttl)}
	return true, nil
}

// Get implements store.Store.
func (s *Store) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok || !s.clock().Before(e.expiresAt) {
		return nil, false, nil
	}
	return cloneBytes(e.value), true, nil
}

// GetDel implements store.Store.
func (s *Store) GetDel(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	delete(s.entries, key)
	if !ok || !s.clock().Before(e.expiresAt) {
		return nil, false, nil
	}
	return cloneBytes(e.value), true, nil
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
