// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostendorf-cloud/govue/analytics"

	"github.com/ostendorf-cloud/burnlink/internal/config"
)

const testWebsiteID = "0b1d3a52-7c0e-4f55-9f3c-2f6a7d8e9c10"

// umamiStub records every body Umami would receive.
type umamiStub struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies []string
}

func newUmamiStub(t *testing.T, handle func(w http.ResponseWriter)) *umamiStub {
	t.Helper()
	s := &umamiStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(b))
		s.mu.Unlock()
		if handle != nil {
			handle(w)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *umamiStub) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bodies...)
}

// counting is a public handler wired to a stub Umami through the real chain.
type counting struct {
	handler http.Handler
	views   *analytics.Client
	stub    *umamiStub
}

func newCounting(t *testing.T, stub *umamiStub) *counting {
	t.Helper()
	cfg, err := config.Load(func(key string) string {
		return map[string]string{
			"STORE_ADDR":       "store.invalid:6379",
			"UMAMI_URL":        stub.srv.URL,
			"UMAMI_WEBSITE_ID": testWebsiteID,
			// The port must not reach Umami: only the bare host does.
			"SITE_URL":        "https://burnlink.test:8443",
			"TRUSTED_PROXIES": "10.0.0.0/8",
		}[key]
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	views, err := newViews(testLogger(), cfg, nil)
	if err != nil {
		t.Fatalf("newViews() error = %v", err)
	}
	handler, err := buildPublicHandler(testLogger(), cfg, testVault(), views)
	if err != nil {
		t.Fatalf("buildPublicHandler() error = %v", err)
	}
	return &counting{handler: handler, views: views, stub: stub}
}

type reqOpt func(*http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

// get sends a browser like GET from a public visitor behind the trusted proxy.
func (c *counting) get(t *testing.T, path string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.RemoteAddr = "10.1.2.3:4000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec
}

// flushed closes the client, which sends what is queued, and returns what the
// stub received decoded.
func (c *counting) flushed(t *testing.T) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.views.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	var out []map[string]any
	for _, b := range c.stub.received() {
		var m map[string]any
		if err := json.Unmarshal([]byte(b), &m); err != nil {
			t.Fatalf("stub got a body that is no JSON: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func payloadOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	p, ok := m["payload"].(map[string]any)
	if !ok {
		t.Fatalf("no payload in %v", m)
	}
	return p
}

func TestAnalyticsCountsOnePatternForEveryRequestLinkID(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))

	for _, path := range []string{"/r/idOneAAAAAAAA", "/r/idTwoBBBBBBBB?token=abc"} {
		if rec := c.get(t, path); rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}
	got := c.flushed(t)
	if len(got) != 2 {
		t.Fatalf("stub received %d views, want 2", len(got))
	}
	for _, m := range got {
		p := payloadOf(t, m)
		if p["url"] != "/r/{id}" {
			t.Errorf("url = %v, want the route pattern /r/{id}", p["url"])
		}
		if _, ok := m["name"]; ok {
			t.Errorf("a view carries an event name: %v", m)
		}
		if _, ok := p["name"]; ok {
			t.Errorf("a view carries an event name: %v", p)
		}
	}
	for _, b := range c.stub.received() {
		for _, secret := range []string{"idOne", "idTwo", "token", "abc"} {
			if strings.Contains(b, secret) {
				t.Errorf("a reported view holds %q: %s", secret, b)
			}
		}
	}
}

func TestAnalyticsCountsOnePatternForEverySecretLinkID(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))

	for _, path := range []string{"/s/idOneAAAAAAAA", "/s/idTwoBBBBBBBB?token=abc"} {
		if rec := c.get(t, path); rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}
	got := c.flushed(t)
	if len(got) != 2 {
		t.Fatalf("stub received %d views, want 2", len(got))
	}
	for _, m := range got {
		if p := payloadOf(t, m); p["url"] != "/s/{id}" {
			t.Errorf("url = %v, want the route pattern /s/{id}", p["url"])
		}
	}
	for _, b := range c.stub.received() {
		for _, secret := range []string{"idOne", "idTwo", "token", "abc"} {
			if strings.Contains(b, secret) {
				t.Errorf("a reported view holds %q: %s", secret, b)
			}
		}
	}
}

func TestAnalyticsCountsThePagesByPattern(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))

	for _, path := range []string{"/", "/security"} {
		if rec := c.get(t, path); rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}
	got := c.flushed(t)
	urls := map[string]bool{}
	for _, m := range got {
		if u, ok := payloadOf(t, m)["url"].(string); ok {
			urls[u] = true
		}
		if payloadOf(t, m)["hostname"] != "burnlink.test" {
			t.Errorf("hostname = %v, want burnlink.test", payloadOf(t, m)["hostname"])
		}
	}
	if len(got) != 2 || !urls["/"] || !urls["/security"] {
		t.Errorf("reported %v, want exactly / and /security", urls)
	}
}

// TestAnalyticsCountsNoAPIRouteAndNoAsset covers the API (answered as JSON and
// by prefix), a static asset, a directory, an unknown path and a nested path
// under the request link route, none of which is a page.
func TestAnalyticsCountsNoAPIRouteAndNoAsset(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))

	for _, path := range []string{
		"/api/v1/config",
		"/api/v1/version",
		"/api/v1/nothing",
		"/assets/app.js",
		"/assets/",
		"/no-such-page",
		"/r/a/b",
		"/r/",
		"/s/a/b",
		"/s/",
		"/healthz",
		"/metrics",
	} {
		c.get(t, path)
	}
	if got := c.flushed(t); len(got) != 0 {
		t.Fatalf("stub received %d views, want none: %v", len(got), got)
	}
}

// TestAnalyticsSkipsAnAPIPathEvenWhenItAnswersHTML pins the wiring's own Skip:
// the API stays out whatever content type a handler returns.
func TestAnalyticsSkipsAnAPIPathEvenWhenItAnswersHTML(t *testing.T) {
	stub := newUmamiStub(t, nil)
	cfg, err := config.Load(func(key string) string {
		return map[string]string{
			"STORE_ADDR": "store.invalid:6379", "UMAMI_URL": stub.srv.URL,
			"UMAMI_WEBSITE_ID": testWebsiteID, "SITE_URL": "https://burnlink.test",
			"TRUSTED_PROXIES": "10.0.0.0/8",
		}[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	views, err := newViews(testLogger(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/page", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})
	c := &counting{handler: views.Middleware(mux), views: views, stub: stub}
	if rec := c.get(t, "/api/v1/page"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := c.flushed(t); len(got) != 0 {
		t.Fatalf("an API path was counted: %v", got)
	}
}

func TestAnalyticsExcludesEachSignalAndAddress(t *testing.T) {
	tests := []struct {
		name string
		opts []reqOpt
	}{
		{"Do Not Track", []reqOpt{header("DNT", "1")}},
		{"Global Privacy Control", []reqOpt{header("Sec-GPC", "1")}},
		{"prefetch", []reqOpt{header("Sec-Purpose", "prefetch")}},
		{"not a document", []reqOpt{header("Sec-Fetch-Dest", "iframe")}},
		{"private client address", []reqOpt{header("X-Forwarded-For", "192.168.1.5")}},
		{"bot", []reqOpt{header("User-Agent", "Googlebot/2.1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCounting(t, newUmamiStub(t, nil))
			if rec := c.get(t, "/security", tt.opts...); rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: the page is still served", rec.Code)
			}
			if got := c.flushed(t); len(got) != 0 {
				t.Fatalf("stub received %d views, want none", len(got))
			}
		})
	}
}

func TestAnalyticsMasksTheClientAddress(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))
	c.get(t, "/security")
	got := c.flushed(t)
	if len(got) != 1 {
		t.Fatalf("stub received %d views, want 1", len(got))
	}
	if ip := payloadOf(t, got[0])["ip"]; ip != "198.51.100.0" {
		t.Errorf("ip = %v, want the /24 198.51.100.0", ip)
	}
}

func TestAnalyticsNeverDelaysOrFailsAResponse(t *testing.T) {
	tests := []struct {
		name   string
		handle func(release <-chan struct{}) func(http.ResponseWriter)
	}{
		{"blocking umami", func(release <-chan struct{}) func(http.ResponseWriter) {
			return func(http.ResponseWriter) { <-release }
		}},
		{"failing umami", func(<-chan struct{}) func(http.ResponseWriter) {
			return func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := make(chan struct{})
			stub := newUmamiStub(t, tt.handle(release))
			c := newCounting(t, stub)
			// Cleanups run last in, first out: release the stub first, then
			// close the client so its workers end, then the stub closes.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = c.views.Close(ctx)
			})
			t.Cleanup(func() { close(release) })

			done := make(chan int, 1)
			go func() { done <- c.get(t, "/security").Code }()
			select {
			case code := <-done:
				if code != http.StatusOK {
					t.Fatalf("status = %d, want 200", code)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the response waited for Umami")
			}
		})
	}
}

func TestWithoutUmamiNothingIsCountedAndPagesAreServed(t *testing.T) {
	handler, err := buildHandler(testLogger(), testConfig(t), testVault())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/security", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
