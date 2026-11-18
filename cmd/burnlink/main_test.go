// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ostendorf-cloud/govue/health"

	"github.com/ostendorf-cloud/burnlink/internal/config"
	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/memstore"
	"github.com/ostendorf-cloud/burnlink/internal/store/redisstore"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// testConfig is the configuration a deployment gets with only STORE_ADDR set.
func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(key string) string {
		if key == "STORE_ADDR" {
			return "store.invalid:6379"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg
}

// memBackend is the in process store with the probe Secrets needs.
type memBackend struct{ *memstore.Store }

func (memBackend) Ping(context.Context) error { return nil }

func testVault() *store.Secrets { return store.NewSecrets(memBackend{memstore.New()}) }

// TestPublicHandlerServesTheSecretAPI proves the five endpoints are routed in
// the real handler, behind the security headers, and that the API answers
// before the file server could.
func TestPublicHandlerServesTheSecretAPI(t *testing.T) {
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	for _, path := range []string{"/api/v1/config", "/api/v1/version"} {
		rec := do(http.MethodGet, path, "")
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s = %d, Cache-Control %q", path, rec.Code, rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("X-Content-Type-Options") == "" {
			t.Errorf("GET %s lost the security headers", path)
		}
	}

	created := do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"c2VjcmV0"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/secrets = %d, body %s", created.Code, created.Body)
	}
	var out struct{ ID string }
	if err := json.Unmarshal(created.Body.Bytes(), &out); err != nil || out.ID == "" {
		t.Fatalf("created body %s: %v", created.Body, err)
	}
	if rec := do(http.MethodHead, "/api/v1/secrets/"+out.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("HEAD = %d, want 200", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/v1/secrets/"+out.ID+"/open", "{}"); rec.Code != http.StatusOK {
		t.Errorf("open = %d, want 200", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/v1/secrets/"+out.ID+"/open", "{}"); rec.Code != http.StatusNotFound {
		t.Errorf("second open = %d, want 404", rec.Code)
	}
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

	if _, err := buildHandler(testLogger(), testConfig(t), testVault()); err != nil {
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
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
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
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
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
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
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

// TestPublicHandlerSPAFallback proves exactly the paths App.vue knows answer
// with index.html, with the security headers still applied, and that every
// other path, the API's included, keeps answering 404.
func TestPublicHandlerSPAFallback(t *testing.T) {
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}

	tests := []struct {
		name     string
		method   string
		path     string
		want     int
		wantHTML bool
	}{
		{"request link", http.MethodGet, "/r/abc123", http.StatusOK, true},
		{"request link with query", http.MethodGet, "/r/abc123?x=1", http.StatusOK, true},
		{"request link head", http.MethodHead, "/r/abc123", http.StatusOK, false},
		{"request link odd characters", http.MethodGet, "/r/a-b_c.d~e", http.StatusOK, true},
		{"request link escaped slash", http.MethodGet, "/r/a%2Fb", http.StatusOK, true},
		{"request link trailing slash", http.MethodGet, "/r/abc123/", http.StatusNotFound, false},
		{"request link empty id", http.MethodGet, "/r/", http.StatusNotFound, false},
		{"request link bare prefix", http.MethodGet, "/r", http.StatusNotFound, false},
		{"request link nested", http.MethodGet, "/r/a/b", http.StatusNotFound, false},
		{"request link post", http.MethodPost, "/r/abc123", http.StatusNotFound, false},
		{"unknown path", http.MethodGet, "/no-such-page", http.StatusNotFound, false},
		{"api unknown", http.MethodGet, "/api/v1/nothing", http.StatusNotFound, false},
		{"api request link path", http.MethodGet, "/api/v1/request-links/abc123", http.StatusNotFound, false},
		{"api under r", http.MethodGet, "/r/api/v1/x", http.StatusNotFound, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, rec.Code, tt.want)
			}
			if tt.want != http.StatusOK {
				if strings.Contains(rec.Body.String(), "<html") {
					t.Fatalf("%s %s answered with HTML on a status %d", tt.method, tt.path, rec.Code)
				}
				return
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Errorf("%s %s Content-Type = %q, want text/html", tt.method, tt.path, got)
			}
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Errorf("%s %s lost its Content-Security-Policy header", tt.method, tt.path)
			}
			if rec.Header().Get("X-Content-Type-Options") == "" {
				t.Errorf("%s %s lost its X-Content-Type-Options header", tt.method, tt.path)
			}
			hasHTML := strings.Contains(rec.Body.String(), "<html")
			if hasHTML != tt.wantHTML {
				t.Errorf("%s %s body has html = %t, want %t", tt.method, tt.path, hasHTML, tt.wantHTML)
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

// switchPinger is a store whose reachability a test flips.
type switchPinger struct{ down atomic.Bool }

func (p *switchPinger) Ping(context.Context) error {
	if p.down.Load() {
		return errors.New("store unreachable")
	}
	return nil
}

// TestReadinessFollowsTheStore proves readiness reports unready while the
// store is unreachable, ready again when it returns, and that liveness never
// depends on it.
func TestReadinessFollowsTheStore(t *testing.T) {
	registry := health.New()
	p := &switchPinger{}
	addStoreCheck(registry, p)
	handler := buildAdminHandler(testLogger(), registry)

	status := func(path string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	cases := []struct {
		name      string
		down      bool
		wantReady int
	}{
		{"store up", false, http.StatusOK},
		{"store down", true, http.StatusServiceUnavailable},
		{"store back", false, http.StatusOK},
	}
	for _, tc := range cases {
		p.down.Store(tc.down)
		if got := status("/readyz"); got != tc.wantReady {
			t.Errorf("%s: GET /readyz status = %d, want %d", tc.name, got, tc.wantReady)
		}
		if got := status("/healthz"); got != http.StatusOK {
			t.Errorf("%s: GET /healthz status = %d, want %d", tc.name, got, http.StatusOK)
		}
	}
}

// TestReadinessWithTheRealClientAgainstAClosedPort wires the production
// client, not a fake, to an address nothing listens on. It needs no server.
func TestReadinessWithTheRealClientAgainstAClosedPort(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	client, err := redisstore.New(redisstore.Options{Addr: addr})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	registry := health.New()
	addStoreCheck(registry, store.NewSecrets(client))
	handler := buildAdminHandler(testLogger(), registry)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
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
