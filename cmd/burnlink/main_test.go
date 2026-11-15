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

// TestPublicHandlerServesIndexHTMLOnSecurityPath proves the security page's
// path answers with the SPA instead of a 404.
func TestPublicHandlerServesIndexHTMLOnSecurityPath(t *testing.T) {
	handler, err := buildHandler(testLogger())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/security", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("GET /security body does not look like index.html: %q", rec.Body.String())
	}
}

// TestPublicHandlerSecurityPathStaysNarrow proves the /security route does
// not widen what the server answers: a trailing slash, an unknown path and
// a non-GET method keep their previous status.
func TestPublicHandlerSecurityPathStaysNarrow(t *testing.T) {
	handler, err := buildHandler(testLogger())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"trailing slash", http.MethodGet, "/security/", http.StatusNotFound},
		{"unknown path", http.MethodGet, "/no-such-page", http.StatusNotFound},
		// The catch-all file server owns every method but GET on this path,
		// exactly as before /security had a route of its own.
		{"post", http.MethodPost, "/security", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, rec.Code, tt.want)
			}
		})
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
