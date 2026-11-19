// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const umamiID = "0b1d3a52-7c0e-4f55-9f3c-2f6a7d8e9c10"

func TestLoadUmamiIsOffByDefault(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Umami.Enabled() {
		t.Error("Umami is enabled with nothing set")
	}
}

func TestLoadUmamiReadsBothValuesAndTheHost(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(map[string]string{
		"UMAMI_URL":        "https://umami.example.test",
		"UMAMI_WEBSITE_ID": umamiID,
		"SITE_HOST":        "burnlink.example.test",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !cfg.Umami.Enabled() || cfg.Umami.WebsiteID != umamiID {
		t.Errorf("Umami = %+v, want enabled with the website id", cfg.Umami)
	}
	if cfg.SiteHost != "burnlink.example.test" {
		t.Errorf("SiteHost = %q", cfg.SiteHost)
	}
}

func TestLoadUmamiRejectsHalfAPairAndAMissingHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"url only", map[string]string{"UMAMI_URL": "https://umami.example.test"}, "UMAMI_URL and UMAMI_WEBSITE_ID"},
		{"id only", map[string]string{"UMAMI_WEBSITE_ID": umamiID}, "UMAMI_URL and UMAMI_WEBSITE_ID"},
		{"no host", map[string]string{"UMAMI_URL": "https://umami.example.test", "UMAMI_WEBSITE_ID": umamiID}, "SITE_HOST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(env(withStore(tt.env)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
