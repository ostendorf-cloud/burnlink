// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ostendorf-cloud/govue/health"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestEmbeddedDistBuildsAWorkingHandler proves the embedded dist filesystem is
// shaped the way buildHandler expects, without starting a server or binding a
// port: a build with an empty or mis-shaped frontend build fails here instead
// of at a request.
func TestEmbeddedDistBuildsAWorkingHandler(t *testing.T) {
	dist, err := fs.Sub(distFS, "dist")
	if err != nil {
		t.Fatalf("fs.Sub(distFS, \"dist\") error = %v", err)
	}

	if _, err := buildHandler(testLogger()); err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	if _, err := fs.Stat(dist, "index.html"); err != nil {
		t.Fatalf("embedded dist has no index.html: %v", err)
	}
}

// TestPublicHandlerServesIndexHTML proves a request to the public handler's
// root path actually answers with the built SPA's index.html, not just that
// the embedded filesystem contains one.
func TestPublicHandlerServesIndexHTML(t *testing.T) {
	handler, err := buildHandler(testLogger())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("GET / body does not look like index.html: %q", rec.Body.String())
	}
}

// TestAdminHandlerAnswersHealthAndReady proves the admin handler wires
// govue's health registry onto /healthz and /readyz, both answering 200 for
// a registry with no checks registered and not draining.
func TestAdminHandlerAnswersHealthAndReady(t *testing.T) {
	registry := health.New()
	handler := buildAdminHandler(testLogger(), registry)

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

// TestAdminHandlerAnswersMetrics proves the admin handler serves a
// Prometheus scrape at /metrics.
func TestAdminHandlerAnswersMetrics(t *testing.T) {
	handler := buildAdminHandler(testLogger(), health.New())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", rec.Code, http.StatusOK)
	}
}
