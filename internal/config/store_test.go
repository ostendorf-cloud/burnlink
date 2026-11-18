// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Obvious dummies, never a real credential.
const (
	dummyUser     = "dummy-user"
	dummyPassword = "dummy-password-not-real"
)

// writeFile writes content into a temp file and returns its path.
func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestLoadStore(t *testing.T) {
	t.Parallel()

	userFile := writeFile(t, dummyUser+"\n")
	passFile := writeFile(t, dummyPassword+"\n")

	cases := []struct {
		name string
		env  map[string]string
		want Store
	}{
		{
			name: "address only",
			env:  map[string]string{"STORE_ADDR": "dragonfly:6379"},
			want: Store{Addr: "dragonfly:6379"},
		},
		{
			name: "direct credentials and tls",
			env: map[string]string{
				"STORE_ADDR": "dragonfly:6379", "STORE_USERNAME": dummyUser,
				"STORE_PASSWORD": dummyPassword, "STORE_TLS": "true",
			},
			want: Store{Addr: "dragonfly:6379", Username: dummyUser, Password: dummyPassword, TLS: true},
		},
		{
			name: "credentials from files",
			env: map[string]string{
				"STORE_ADDR": "[::1]:6379", "STORE_USERNAME_FILE": userFile, "STORE_PASSWORD_FILE": passFile,
			},
			want: Store{Addr: "[::1]:6379", Username: dummyUser, Password: dummyPassword},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(env(tc.env))
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if cfg.Store != tc.want {
				t.Errorf("Store = %#v, want %#v", cfg.Store, tc.want)
			}
		})
	}
}

func TestLoadStoreRejects(t *testing.T) {
	t.Parallel()

	missingFile := filepath.Join(t.TempDir(), "absent")
	passFile := writeFile(t, dummyPassword)

	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing address", map[string]string{}, "STORE_ADDR"},
		{"address without port", map[string]string{"STORE_ADDR": "dragonfly"}, "STORE_ADDR"},
		{"address with port zero", map[string]string{"STORE_ADDR": "dragonfly:0"}, "STORE_ADDR"},
		{"address with text port", map[string]string{"STORE_ADDR": "dragonfly:http"}, "STORE_ADDR"},
		{"address without host", map[string]string{"STORE_ADDR": ":6379"}, "STORE_ADDR"},
		{"bad tls flag", map[string]string{"STORE_ADDR": "a:1", "STORE_TLS": "maybe"}, "STORE_TLS"},
		{
			"password and its file",
			map[string]string{
				"STORE_ADDR": "a:1", "STORE_PASSWORD": dummyPassword, "STORE_PASSWORD_FILE": passFile,
			},
			"STORE_PASSWORD",
		},
		{"unreadable password file", map[string]string{"STORE_ADDR": "a:1", "STORE_PASSWORD_FILE": missingFile}, "STORE_PASSWORD"},
		{
			"empty username file",
			map[string]string{"STORE_ADDR": "a:1", "STORE_USERNAME_FILE": writeFile(t, "\n")},
			"STORE_USERNAME",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(env(tc.env))
			if err == nil {
				t.Fatal("Load() error = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// TestLoadAggregatesEveryProblem proves one start reports every mistake,
// store and non store alike, not one per restart.
func TestLoadAggregatesEveryProblem(t *testing.T) {
	t.Parallel()

	_, err := Load(env(map[string]string{
		"STORE_ADDR":          "no-port",
		"STORE_TLS":           "maybe",
		"STORE_PASSWORD":      dummyPassword,
		"STORE_PASSWORD_FILE": "/nonexistent/path",
		"LOG_LEVEL":           "verbose",
	}))
	if err == nil {
		t.Fatal("Load() error = nil, want an error")
	}
	for _, want := range []string{"STORE_ADDR", "STORE_TLS", "STORE_PASSWORD", "verbose"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %q, want it to mention %q", err, want)
		}
	}
}

// TestLoadNeverEchoesACredential covers the paths where a credential could
// end up in an error or in a printed Config.
func TestLoadNeverEchoesACredential(t *testing.T) {
	t.Parallel()

	// A URL with credentials pasted into the address.
	_, err := Load(env(map[string]string{"STORE_ADDR": "redis://" + dummyUser + ":" + dummyPassword + "@host"}))
	if err == nil {
		t.Fatal("Load() error = nil, want an error")
	}
	if strings.Contains(err.Error(), dummyPassword) {
		t.Errorf("Load() error leaks the password: %q", err)
	}

	// The password set twice.
	_, err = Load(env(map[string]string{
		"STORE_ADDR": "a:1", "STORE_PASSWORD": dummyPassword, "STORE_PASSWORD_FILE": "/x",
	}))
	if err == nil || strings.Contains(err.Error(), dummyPassword) {
		t.Errorf("Load() error = %v, want an error without the password", err)
	}

	cfg, err := Load(env(map[string]string{
		"STORE_ADDR": "a:1", "STORE_USERNAME": dummyUser, "STORE_PASSWORD": dummyPassword,
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, cfg)
		if strings.Contains(out, dummyPassword) || strings.Contains(out, dummyUser) {
			t.Errorf("Sprintf(%q, cfg) leaks a credential: %s", format, out)
		}
	}
}
