// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package memstore

import (
	"context"
	"testing"
	"time"
)

func TestSetNXWritesOnlyWhenTheKeyIsAbsent(t *testing.T) {
	t.Parallel()

	s := New()
	ctx := context.Background()

	ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute)
	if err != nil || !ok {
		t.Fatalf("first SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	ok, err = s.SetNX(ctx, "k", []byte("b"), time.Minute)
	if err != nil || ok {
		t.Fatalf("second SetNX = (%v, %v), want (false, nil)", ok, err)
	}

	value, found, err := s.Get(ctx, "k")
	if err != nil || !found || string(value) != "a" {
		t.Fatalf("Get = (%q, %v, %v), want (\"a\", true, nil): the second write must not have won", value, found, err)
	}
}

func TestSetNXRejectsANonPositiveTTL(t *testing.T) {
	t.Parallel()

	s := New()
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Second} {
		if ok, err := s.SetNX(ctx, "k", []byte("a"), ttl); err == nil || ok {
			t.Errorf("SetNX(ttl=%v) = (%v, %v), want an error", ttl, ok, err)
		}
	}
}

func TestSetNXCanWriteAgainOnceTheOldValueHasExpired(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	s := New()
	s.Now = func() time.Time { return now }
	ctx := context.Background()

	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("first SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	now = now.Add(time.Minute)
	ok, err := s.SetNX(ctx, "k", []byte("b"), time.Minute)
	if err != nil || !ok {
		t.Fatalf("SetNX after expiry = (%v, %v), want (true, nil)", ok, err)
	}

	value, found, err := s.Get(ctx, "k")
	if err != nil || !found || string(value) != "b" {
		t.Fatalf("Get = (%q, %v, %v), want (\"b\", true, nil)", value, found, err)
	}
}

func TestGetReportsFalseForAnUnknownKey(t *testing.T) {
	t.Parallel()

	s := New()
	value, found, err := s.Get(context.Background(), "missing")
	if err != nil || found || value != nil {
		t.Fatalf("Get(missing) = (%v, %v, %v), want (nil, false, nil)", value, found, err)
	}
}

func TestGetReportsFalseOnceTheValueHasExpired(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	s := New()
	s.Now = func() time.Time { return now }
	ctx := context.Background()

	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	now = now.Add(time.Minute)
	value, found, err := s.Get(ctx, "k")
	if err != nil || found || value != nil {
		t.Fatalf("Get after expiry = (%v, %v, %v), want (nil, false, nil)", value, found, err)
	}
}

func TestGetDoesNotRemoveTheValue(t *testing.T) {
	t.Parallel()

	s := New()
	ctx := context.Background()
	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	for i := 0; i < 3; i++ {
		value, found, err := s.Get(ctx, "k")
		if err != nil || !found || string(value) != "a" {
			t.Fatalf("Get call %d = (%q, %v, %v), want (\"a\", true, nil)", i, value, found, err)
		}
	}
}

func TestGetDelRemovesTheValueOnTheFirstCallOnly(t *testing.T) {
	t.Parallel()

	s := New()
	ctx := context.Background()
	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	value, found, err := s.GetDel(ctx, "k")
	if err != nil || !found || string(value) != "a" {
		t.Fatalf("first GetDel = (%q, %v, %v), want (\"a\", true, nil)", value, found, err)
	}

	value, found, err = s.GetDel(ctx, "k")
	if err != nil || found || value != nil {
		t.Fatalf("second GetDel = (%v, %v, %v), want (nil, false, nil)", value, found, err)
	}
}

func TestGetDelReportsFalseForAnExpiredValueAndStillRemovesIt(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	s := New()
	s.Now = func() time.Time { return now }
	ctx := context.Background()
	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
	}

	now = now.Add(time.Minute)
	value, found, err := s.GetDel(ctx, "k")
	if err != nil || found || value != nil {
		t.Fatalf("GetDel after expiry = (%v, %v, %v), want (nil, false, nil)", value, found, err)
	}

	if _, found, _ := s.Get(ctx, "k"); found {
		t.Fatalf("Get after GetDel = found, want the expired entry gone")
	}
}

func TestStoredValuesAreIndependentOfTheCallersSlice(t *testing.T) {
	t.Parallel()

	s := New()
	ctx := context.Background()
	original := []byte("a")
	if ok, err := s.SetNX(ctx, "k", original, time.Minute); err != nil || !ok {
		t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
	}
	original[0] = 'z'

	value, _, err := s.Get(ctx, "k")
	if err != nil || string(value) != "a" {
		t.Fatalf("Get = (%q, %v), want (\"a\", nil): mutating the caller's slice must not reach the store", value, err)
	}
}
