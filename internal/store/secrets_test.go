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
	getErr   error
	setCalls int
}

func (f *fake) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	f.setCalls++
	if f.failWith != nil {
		return false, f.failWith
	}
	return f.Store.SetNX(ctx, key, value, ttl)
}

func (f *fake) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	return f.Store.Get(ctx, key)
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

// TestKeyspacesDoNotMeet proves a secret id cannot reach a request link key
// and a request link key cannot reach a secret, whatever the id says.
func TestKeyspacesDoNotMeet(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	// The two key shapes internal/webapp/requestlink writes.
	linkKeys := []string{"requestlink:abc", "requestlink:abc:submission:0"}

	for _, key := range linkKeys {
		t.Run("secret id "+key, func(t *testing.T) {
			t.Parallel()

			f, _ := newFake()
			s := store.NewSecrets(f)
			if _, err := f.SetNX(ctx, key, []byte("link data"), time.Minute); err != nil {
				t.Fatalf("SetNX() error = %v", err)
			}

			// Take with the link key as the id finds nothing and deletes nothing.
			if _, err := s.Take(ctx, key); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Take(%q) error = %v, want ErrNotFound", key, err)
			}
			// Put with the link key as the id does not collide with the link data.
			if err := s.Put(ctx, key, []byte("secret"), time.Minute); err != nil {
				t.Errorf("Put(%q) error = %v, want nil", key, err)
			}
			got, ok, err := f.Get(ctx, key)
			if err != nil || !ok || string(got) != "link data" {
				t.Errorf("link key %q = %q, %v, %v, want it untouched", key, got, ok, err)
			}
		})
	}

	t.Run("a secret is not readable as a plain key", func(t *testing.T) {
		t.Parallel()

		f, _ := newFake()
		s := store.NewSecrets(f)
		mustNil(t, s.Put(ctx, "abc", []byte("secret"), time.Minute))
		if _, ok, _ := f.Get(ctx, "abc"); ok {
			t.Error("raw key abc exists, want the secret under its prefix only")
		}
		if _, ok, _ := f.Get(ctx, store.SecretKeyPrefix+"abc"); !ok {
			t.Errorf("key %q missing", store.SecretKeyPrefix+"abc")
		}
	})
}

func TestTakeBackendFailureIsNotNotFound(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	f.failWith = errBoom
	_, err := store.NewSecrets(f).Take(t.Context(), "id")
	wantBackendError(t, err)
}

func TestExists(t *testing.T) {
	t.Parallel()

	f, now := newFake()
	s := store.NewSecrets(f)
	ctx := t.Context()
	mustNil(t, s.Put(ctx, "live", []byte("secret"), time.Minute))
	mustNil(t, s.Put(ctx, "short", []byte("secret"), time.Second))

	for range 3 {
		ok, err := s.Exists(ctx, "live")
		mustNil(t, err)
		if !ok {
			t.Fatal("Exists(live) = false, want true on every call")
		}
	}
	// Asking never consumed it.
	got, err := s.Take(ctx, "live")
	mustNil(t, err)
	if string(got) != "secret" {
		t.Errorf("Take() after Exists = %q, want the secret", got)
	}
	if ok, _ := s.Exists(ctx, "live"); ok {
		t.Error("Exists(live) after Take = true, want false")
	}
	if ok, _ := s.Exists(ctx, "unknown"); ok {
		t.Error("Exists(unknown) = true, want false")
	}
	*now = now.Add(time.Minute)
	if ok, _ := s.Exists(ctx, "short"); ok {
		t.Error("Exists(expired) = true, want false")
	}

	f.getErr = errBoom
	_, err = s.Exists(ctx, "live")
	wantBackendError(t, err)
}

func TestPutTargetAndTakeTarget(t *testing.T) {
	t.Parallel()

	f, now := newFake()
	s := store.NewSecrets(f)
	ctx := t.Context()
	const target = "https://hooks.example.com/x"

	mustNil(t, s.PutTarget(ctx, "id", target, time.Minute))
	if err := s.PutTarget(ctx, "id", "https://other.example.com/", time.Minute); !errors.Is(err, store.ErrExists) {
		t.Errorf("second PutTarget() error = %v, want ErrExists", err)
	}

	got, err := s.TakeTarget(ctx, "id")
	mustNil(t, err)
	if got != target {
		t.Errorf("TakeTarget() = %q, want the first value", got)
	}
	// Taken once: gone for the next reader.
	got, err = s.TakeTarget(ctx, "id")
	mustNil(t, err)
	if got != "" {
		t.Errorf("second TakeTarget() = %q, want empty", got)
	}

	// No target is the default, not an error.
	got, err = s.TakeTarget(ctx, "never-set")
	mustNil(t, err)
	if got != "" {
		t.Errorf("TakeTarget(unknown) = %q, want empty", got)
	}

	// The target ends with the lifetime it was given.
	mustNil(t, s.PutTarget(ctx, "short", target, time.Second))
	*now = now.Add(time.Second)
	got, err = s.TakeTarget(ctx, "short")
	mustNil(t, err)
	if got != "" {
		t.Errorf("TakeTarget(expired) = %q, want empty", got)
	}
}

func TestTargetIsSeparateFromTheSecret(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	s := store.NewSecrets(f)
	ctx := t.Context()
	mustNil(t, s.Put(ctx, "id", []byte("cipher"), time.Minute))
	mustNil(t, s.PutTarget(ctx, "id", "https://hooks.example.com/x", time.Minute))

	// The secret's stored bytes are the ciphertext and nothing else.
	raw, ok, err := f.Get(ctx, store.SecretKeyPrefix+"id")
	mustNil(t, err)
	if !ok || string(raw) != "cipher" {
		t.Errorf("secret key = %q, %v, want the ciphertext untouched", raw, ok)
	}
	// Taking the secret leaves the target for TakeTarget, and the reverse.
	got, err := s.Take(ctx, "id")
	mustNil(t, err)
	if string(got) != "cipher" {
		t.Errorf("Take() = %q, want the ciphertext", got)
	}
	target, err := s.TakeTarget(ctx, "id")
	mustNil(t, err)
	if target != "https://hooks.example.com/x" {
		t.Errorf("TakeTarget() = %q, want the target", target)
	}
}

func TestPutTargetRefusesANonPositiveTTL(t *testing.T) {
	t.Parallel()

	for _, ttl := range []time.Duration{0, -time.Second} {
		f, _ := newFake()
		wantError(t, store.NewSecrets(f).PutTarget(t.Context(), "id", "https://hooks.example.com/x", ttl))
		if f.setCalls != 0 {
			t.Errorf("ttl %v reached the store (%d calls)", ttl, f.setCalls)
		}
	}
}

func TestTargetBackendFailureIsNotASentinel(t *testing.T) {
	t.Parallel()

	f, _ := newFake()
	f.failWith = errBoom
	s := store.NewSecrets(f)
	wantBackendError(t, s.PutTarget(t.Context(), "id", "https://hooks.example.com/x", time.Minute))
	_, err := s.TakeTarget(t.Context(), "id")
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
