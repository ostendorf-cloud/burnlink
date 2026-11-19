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
		"SITE_URL":         "https://burnlink.example.test:8443",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !cfg.Umami.Enabled() || cfg.Umami.WebsiteID != umamiID {
		t.Errorf("Umami = %+v, want enabled with the website id", cfg.Umami)
	}
	if got := cfg.SiteURL.Hostname(); got != "burnlink.example.test" {
		t.Errorf("SiteURL.Hostname() = %q, want the bare host without the port", got)
	}
}

func TestLoadSiteURLDefaultsAndValidates(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(withStore(map[string]string{
		"UMAMI_URL": "https://umami.example.test", "UMAMI_WEBSITE_ID": umamiID,
	})))
	if err != nil {
		t.Fatalf("Load() error = %v, want the default SITE_URL to satisfy Umami", err)
	}
	if got := cfg.SiteURL.String(); got != DefaultSiteURL {
		t.Errorf("SiteURL = %q, want %q", got, DefaultSiteURL)
	}

	for _, ok := range []string{"https://burnlink.example.test/", "http://localhost:8080"} {
		if _, err := Load(env(withStore(map[string]string{"SITE_URL": ok}))); err != nil {
			t.Errorf("SITE_URL=%q: Load() error = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"burnlink.example.test", "ftp://burnlink.example.test", "https://burnlink.example.test/app",
		"https://burnlink.example.test?x=1", "https://burnlink.example.test#f", "http://burnlink.example.test",
	} {
		_, err := Load(env(withStore(map[string]string{"SITE_URL": bad})))
		if err == nil || !strings.Contains(err.Error(), "SITE_URL") {
			t.Errorf("SITE_URL=%q: Load() error = %v, want one naming SITE_URL", bad, err)
		}
	}
}

func TestLoadUmamiRejectsHalfAPair(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"url only", map[string]string{"UMAMI_URL": "https://umami.example.test"}, "UMAMI_URL and UMAMI_WEBSITE_ID"},
		{"id only", map[string]string{"UMAMI_WEBSITE_ID": umamiID}, "UMAMI_URL and UMAMI_WEBSITE_ID"},
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
