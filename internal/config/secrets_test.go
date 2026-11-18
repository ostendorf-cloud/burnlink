// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadSecretDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := Secrets{
		MaxBytes:        1 << 20,
		LifetimeMin:     time.Minute,
		LifetimeMax:     7 * 24 * time.Hour,
		LifetimeDefault: 24 * time.Hour,
	}
	if cfg.Secrets != want {
		t.Errorf("Secrets = %+v, want %+v", cfg.Secrets, want)
	}
	if cfg.RateLimit != (RateLimit{Burst: 10, Per: time.Minute}) {
		t.Errorf("RateLimit = %+v, want burst 10 per minute", cfg.RateLimit)
	}
}

func TestLoadSecretOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(map[string]string{
		"SECRET_MAX_BYTES":        "2048",
		"SECRET_LIFETIME_MIN":     "30s",
		"SECRET_LIFETIME_MAX":     "2d",
		"SECRET_LIFETIME_DEFAULT": "1h",
		"RATE_LIMIT_BURST":        "3",
		"RATE_LIMIT_PER":          "10s",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := Secrets{MaxBytes: 2048, LifetimeMin: 30 * time.Second, LifetimeMax: 48 * time.Hour, LifetimeDefault: time.Hour}
	if cfg.Secrets != want {
		t.Errorf("Secrets = %+v, want %+v", cfg.Secrets, want)
	}
	if cfg.RateLimit != (RateLimit{Burst: 3, Per: 10 * time.Second}) {
		t.Errorf("RateLimit = %+v", cfg.RateLimit)
	}
}

func TestLoadSecretRejections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"size zero", map[string]string{"SECRET_MAX_BYTES": "0"}, "SECRET_MAX_BYTES"},
		{"size not a number", map[string]string{"SECRET_MAX_BYTES": "big"}, "SECRET_MAX_BYTES"},
		{"size above the hard cap", map[string]string{"SECRET_MAX_BYTES": "999999999"}, "SECRET_MAX_BYTES"},
		{"min above max", map[string]string{"SECRET_LIFETIME_MIN": "2h", "SECRET_LIFETIME_MAX": "1h"}, "must not exceed"},
		{"default above max", map[string]string{"SECRET_LIFETIME_MAX": "1h"}, "SECRET_LIFETIME_DEFAULT"},
		{"default below min", map[string]string{"SECRET_LIFETIME_MIN": "48h", "SECRET_LIFETIME_MAX": "72h"}, "SECRET_LIFETIME_DEFAULT"},
		{"lifetime not a duration", map[string]string{"SECRET_LIFETIME_DEFAULT": "soon"}, "SECRET_LIFETIME_DEFAULT"},
		{"lifetime above the hard cap", map[string]string{"SECRET_LIFETIME_MAX": "90d"}, "SECRET_LIFETIME_MAX"},
		{"min with a fraction of a second", map[string]string{"SECRET_LIFETIME_MIN": "1500ms"}, "whole number of seconds"},
		{"max with a fraction of a second", map[string]string{"SECRET_LIFETIME_MAX": "90m500ms"}, "whole number of seconds"},
		{"default with a fraction of a second", map[string]string{"SECRET_LIFETIME_DEFAULT": "1.5h1ms"}, "whole number of seconds"},
		{"burst zero", map[string]string{"RATE_LIMIT_BURST": "0"}, "RATE_LIMIT_BURST"},
		{"per zero", map[string]string{"RATE_LIMIT_PER": "0s"}, "RATE_LIMIT_PER"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(env(withStore(tc.env)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadAggregatesSecretProblems(t *testing.T) {
	t.Parallel()

	_, err := Load(env(withStore(map[string]string{
		"SECRET_MAX_BYTES": "0",
		"RATE_LIMIT_BURST": "0",
		"LOG_LEVEL":        "verbose",
	})))
	if err == nil {
		t.Fatal("Load() error = nil")
	}
	for _, want := range []string{"SECRET_MAX_BYTES", "RATE_LIMIT_BURST", "log level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}
