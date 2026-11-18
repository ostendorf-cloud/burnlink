// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"log/slog"
	"maps"
	"net/netip"
	"strings"
	"testing"
)

// env builds a getenv function over a fixed map, the shape Load expects. A
// key absent from the map behaves exactly like an unset environment
// variable: envconf's own lookup returns "".
func env(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

// withStore returns a copy of values that carries the one required store
// variable, so a test about another setting does not have to repeat it.
func withStore(values map[string]string) map[string]string {
	out := map[string]string{"STORE_ADDR": "store.invalid:6379"}
	maps.Copy(out, values)
	return out
}

func TestLoadAppliesDefaultsWhenEverythingIsUnset(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want %q", cfg.Addr, ":8080")
	}
	if cfg.AdminAddr != ":8081" {
		t.Errorf("AdminAddr = %q, want %q", cfg.AdminAddr, ":8081")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.TrustedProxies != nil {
		t.Errorf("TrustedProxies = %v, want nil", cfg.TrustedProxies)
	}
}

func TestLoadOverridesEachVariable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		env   map[string]string
		check func(t *testing.T, cfg Config)
	}{
		{
			name: "ADDR",
			env:  map[string]string{"ADDR": ":9090"},
			check: func(t *testing.T, cfg Config) {
				if cfg.Addr != ":9090" {
					t.Errorf("Addr = %q, want %q", cfg.Addr, ":9090")
				}
			},
		},
		{
			name: "ADMIN_ADDR",
			env:  map[string]string{"ADMIN_ADDR": ":9091"},
			check: func(t *testing.T, cfg Config) {
				if cfg.AdminAddr != ":9091" {
					t.Errorf("AdminAddr = %q, want %q", cfg.AdminAddr, ":9091")
				}
			},
		},
		{
			name: "LOG_LEVEL",
			env:  map[string]string{"LOG_LEVEL": "debug"},
			check: func(t *testing.T, cfg Config) {
				if cfg.LogLevel != slog.LevelDebug {
					t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelDebug)
				}
			},
		},
		{
			name: "TRUSTED_PROXY_CIDRS",
			env:  map[string]string{"TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 192.168.1.1"},
			check: func(t *testing.T, cfg Config) {
				want := []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.PrefixFrom(netip.MustParseAddr("192.168.1.1"), 32),
				}
				if len(cfg.TrustedProxies) != len(want) {
					t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
				}
				for i := range want {
					if cfg.TrustedProxies[i] != want[i] {
						t.Errorf("TrustedProxies[%d] = %v, want %v", i, cfg.TrustedProxies[i], want[i])
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(env(withStore(tc.env)))
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			tc.check(t, cfg)
		})
	}
}

func TestLoadRejectsAnInvalidLogLevel(t *testing.T) {
	t.Parallel()

	_, err := Load(env(withStore(map[string]string{"LOG_LEVEL": "verbose"})))
	if err == nil {
		t.Fatal("Load() error = nil, want an error for an invalid LOG_LEVEL")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("Load() error = %q, want it wrapped with \"config:\"", err.Error())
	}
	if !strings.Contains(err.Error(), "verbose") {
		t.Errorf("Load() error = %q, want it to name the invalid value", err.Error())
	}
}

func TestLoadRejectsAnInvalidTrustedProxyCIDR(t *testing.T) {
	t.Parallel()

	_, err := Load(env(withStore(map[string]string{"TRUSTED_PROXY_CIDRS": "not-a-cidr"})))
	if err == nil {
		t.Fatal("Load() error = nil, want an error for an invalid TRUSTED_PROXY_CIDRS entry")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("Load() error = %q, want it wrapped with \"config:\"", err.Error())
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("Load() error = %q, want it to name the invalid value", err.Error())
	}
}
