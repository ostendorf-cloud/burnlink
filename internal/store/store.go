// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package store defines the contract burnlink's HTTP handlers use to talk to
// the Redis-compatible store docs/concepts/burnlink.md names: a value is
// written once with SET NX PX, consumed exactly once with GETDEL, or read
// without being taken at all.
//
// The Redis-compatible client itself, and the ordinary one-time secret's own
// endpoints, are a later milestone (issues #4 and #5). This package exists
// now because the request link's endpoints need something to call; they are
// written against this interface so that milestone can implement it without
// either endpoint's call sites changing.
//
// Known cost: there is no batch primitive, so the request link's open call
// makes one GetDel round trip per slot (up to its concurrent submission
// limit, 50 by default) and a submit against a full link makes up to as many
// SetNX calls. Both are bounded and per address rate limited. A batch method
// would change this interface and every implementation, so it is decided with
// the wiring of the Redis client, against measured latency, not guessed here.
package store

import (
	"context"
	"time"
)

// Store is the minimal key/value contract a handler needs.
//
// SetNX and GetDel are exactly the two primitives docs/concepts/burnlink.md
// settles on: a write that never overwrites an existing value, and a read
// that takes the value with it so two readers cannot both win. Get is the
// third primitive neither endpoint had to name yet: a value consulted more
// than once before it is finally taken, such as a request link's own
// lifetime and limits, needs a read that does not consume it, and so does
// docs/concepts/burnlink.md's own "ask whether it is still there without
// taking it". Keeping Get here rather than inventing a second interface
// keeps every endpoint, present and future, against the same three methods.
type Store interface {
	// SetNX stores value under key with the given time to live, only if key
	// does not already hold a value. It reports whether the write happened.
	// ttl must be positive; a store is free to reject anything else, the
	// same way Redis's PX option does.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Get returns the value stored under key without removing it, and
	// reports whether key held one.
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// GetDel atomically returns and removes the value stored under key, and
	// reports whether key held one. A second call for the same key reports
	// false.
	GetDel(ctx context.Context, key string) ([]byte, bool, error)
}
