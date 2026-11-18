// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/memstore"
)

// These tests cover Secrets' refusals and error mapping against a small
// in process fake. The store's own guarantees (NX, GETDEL, expiry) are proven
// against a real server in internal/store/redisstore.

var errBoom = errors.New("backend down")

// fake is memstore plus the failure switches the error paths need.
type fake struct {
	*memstore.Store
	failWith error
	pingErr  error
	setCalls int
}

func (f *fake) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	f.setCalls++
	if f.failWith != nil {
		return false, f.failWith
	}
	return f.Store.SetNX(ctx, key, value, ttl)
}

func (f *fake) GetDel(ctx context.Context, key string) ([]byte, bool, error) {
	if f.failWith != nil {
		return nil, false, f.failWith
	}
	return f.Store.GetDel(ctx, key)
}

func (f *fake) Ping(context.Context) error { return f.pingErr }

func newFake() (*fake, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := memstore.New()
	m.Now = func() time.Time { return now }
	return &fake{Store: m}, &now
}

func TestPut(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		prepare   func(t *testing.T, f *fake, s *store.Secrets)
		ttl       time.Duration
		check     func(t *testing.T, err error)
		wantCalls int
	}{
		{
			name:      "stores a new id",
			ttl:       time.Minute,
			check:     func(t *testing.T, err error) { mustNil(t, err) },
			wantCalls: 1,
		},
		{
			name: "refuses an existing id with ErrExists",
			prepare: func(t *testing.T, _ *fake, s *store.Secrets) {
				mustNil(t, s.Put(t.Context(), "id", []byte("first"), time.Minute))
			},
			ttl: time.Minute,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, store.ErrExists) {
					t.Errorf("Put() error = %v, want ErrExists", err)
				}
			},
			wantCalls: 2,
		},
		{
			name:      "a backend failure is not ErrExists",
			prepare:   func(_ *testing.T, f *fake, _ *store.Secrets) { f.failWith = errBoom },
			ttl:       time.Minute,
			check:     wantBackendError,
			wantCalls: 1,
		},
		{
			name:  "zero ttl never reaches the store",
			ttl:   0,
			check: wantError,
		},
		{
			name:  "negative ttl never reaches the store",
			ttl:   -time.Second,
			check: wantError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, _ := newFake()
			s := store.NewSecrets(f)
			if tc.prepare != nil {
				tc.prepare(t, f, s)
			}
			err := s.Put(t.Context(), "id", []byte("secret"), tc.ttl)
			tc.check(t, err)
			if tc.wantCalls != 0 && f.setCalls != tc.wantCalls {
				t.Errorf("SetNX calls = %d, want %d", f.setCalls, tc.wantCalls)
			}
			if tc.wantCalls == 0 && f.setCalls != 0 {
				t.Errorf("SetNX calls = %d, want 0", f.setCalls)
			}
		})
	}
}

func TestPutKeepsTheFirstValue(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	s := store.NewSecrets(f)
	mustNil(t, s.Put(t.Context(), "id", []byte("first"), time.Minute))
	if err := s.Put(t.Context(), "id", []byte("second"), time.Minute); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second Put() error = %v, want ErrExists", err)
	}
	got, err := s.Take(t.Context(), "id")
	mustNil(t, err)
	if !bytes.Equal(got, []byte("first")) {
		t.Errorf("Take() = %q, want %q", got, "first")
	}
}

func TestTake(t *testing.T) {
	t.Parallel()

	f, now := newFake()
	s := store.NewSecrets(f)
	ctx := t.Context()

	mustNil(t, s.Put(ctx, "live", []byte("secret"), time.Minute))
	mustNil(t, s.Put(ctx, "taken", []byte("secret"), time.Minute))
	mustNil(t, s.Put(ctx, "expired", []byte("secret"), time.Second))
	if _, err := s.Take(ctx, "taken"); err != nil {
		t.Fatalf("first Take() error = %v", err)
	}
	*now = now.Add(time.Hour)
	mustNil(t, s.Put(ctx, "live2", []byte("secret"), time.Minute))

	got, err := s.Take(ctx, "live2")
	mustNil(t, err)
	if string(got) != "secret" {
		t.Errorf("Take() = %q, want %q", got, "secret")
	}

	// Taken, expired and never existed are one error, the same value.
	causes := map[string]string{"already taken": "taken", "expired": "expired", "never existed": "unknown"}
	var first error
	for cause, id := range causes {
		_, err := s.Take(ctx, id)
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Take(%s) error = %v, want ErrNotFound", cause, err)
		}
		if first == nil {
			first = err
		}
		if err != first { //nolint:errorlint // identity is the point: the very same error value
			t.Errorf("Take(%s) error = %v, differs from the other causes' %v", cause, err, first)
		}
	}
}

func TestTakeBackendFailureIsNotNotFound(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	f.failWith = errBoom
	_, err := store.NewSecrets(f).Take(t.Context(), "id")
	wantBackendError(t, err)
}

func TestPing(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	s := store.NewSecrets(f)
	mustNil(t, s.Ping(t.Context()))

	f.pingErr = errBoom
	err := s.Ping(t.Context())
	if !errors.Is(err, errBoom) {
		t.Errorf("Ping() error = %v, want it to wrap the backend error", err)
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
}

func wantError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("error = nil, want an error")
	}
}

// wantBackendError wants the backend's error, wrapped, and neither of the
// two sentinels: an outage must never read as "not found" or "exists".
func wantBackendError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errBoom) {
		t.Errorf("error = %v, want it to wrap the backend error", err)
	}
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) {
		t.Errorf("error = %v, must not be a sentinel", err)
	}
}
