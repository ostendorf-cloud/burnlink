// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func getPath(t *testing.T, h http.Handler, path string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func publicHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := buildHandler(testLogger(), testConfig(t), testVault())
	if err != nil {
		t.Fatalf("buildHandler() error = %v", err)
	}
	return h
}

func TestLegalAliasesRedirectToTheMatchingLocalePage(t *testing.T) {
	h := publicHandler(t)
	tests := []struct {
		path string
		opts []reqOpt
		want string
	}{
		{"/impressum", nil, "/de/imprint"},
		{"/datenschutz", nil, "/de/privacy"},
		{"/datenschutzerklaerung", nil, "/de/privacy"},
		// A German alias is German whatever the visitor's header says.
		{"/impressum", []reqOpt{header("Accept-Language", "en")}, "/de/imprint"},
		{"/imprint", []reqOpt{header("Accept-Language", "en")}, "/en/imprint"},
		{"/privacy", []reqOpt{header("Accept-Language", "en")}, "/en/privacy"},
		{"/imprint", []reqOpt{header("Accept-Language", "de")}, "/de/imprint"},
		{"/privacy", nil, "/de/privacy"},
	}
	for _, tt := range tests {
		rec := getPath(t, h, tt.path, tt.opts...)
		if rec.Code != http.StatusFound {
			t.Errorf("GET %s = %d, want 302", tt.path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != tt.want {
			t.Errorf("GET %s Location = %q, want %q", tt.path, got, tt.want)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", tt.path, got)
		}
	}
}

func TestLegalPagesAreServedInBothLanguages(t *testing.T) {
	h := publicHandler(t)
	for _, tt := range []struct{ path, lang, text, imprint, privacy string }{
		{"/de/imprint", `lang="de"`, "Frankenstr. 8", `href="/de/imprint"`, `href="/de/privacy"`},
		{"/en/imprint", `lang="en"`, "Frankenstr. 8", `href="/en/imprint"`, `href="/en/privacy"`},
		{"/de/privacy", `lang="de"`, "Datenschutz", `href="/de/imprint"`, `href="/de/privacy"`},
		{"/en/privacy", `lang="en"`, "Page view counting", `href="/en/imprint"`, `href="/en/privacy"`},
	} {
		rec := getPath(t, h, tt.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", tt.path, rec.Code)
		}
		body := rec.Body.String()
		// The footer links the pages of the page's own language.
		for _, want := range []string{tt.lang, tt.text, tt.imprint, tt.privacy} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s misses %q", tt.path, want)
			}
		}
	}
}

func TestSiteWithoutTermsHasNoTermsRoute(t *testing.T) {
	h := publicHandler(t)
	for _, path := range []string{"/terms", "/agb", "/de/terms", "/en/terms"} {
		if rec := getPath(t, h, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: the site has no terms", path, rec.Code)
		}
	}
}

func TestLegalPagesRejectOtherMethodsAndTrailingSlash(t *testing.T) {
	h := publicHandler(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/impressum", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /impressum = %d, want 405", rec.Code)
	}
	if rec := getPath(t, h, "/de/imprint/"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /de/imprint/ = %d, want 404", rec.Code)
	}
}

func TestAnalyticsCountsALegalPageAndNoAlias(t *testing.T) {
	c := newCounting(t, newUmamiStub(t, nil))

	for _, path := range []string{"/impressum", "/datenschutz", "/datenschutzerklaerung", "/imprint", "/privacy"} {
		if rec := c.get(t, path); rec.Code != http.StatusFound {
			t.Fatalf("GET %s = %d, want 302", path, rec.Code)
		}
	}
	if got := c.flushed(t); len(got) != 0 {
		t.Fatalf("a redirect alias was counted: %v", got)
	}

	c = newCounting(t, newUmamiStub(t, nil))
	if rec := c.get(t, "/de/privacy"); rec.Code != http.StatusOK {
		t.Fatalf("GET /de/privacy = %d, want 200", rec.Code)
	}
	got := c.flushed(t)
	if len(got) != 1 || payloadOf(t, got[0])["url"] != "/de/privacy" {
		t.Fatalf("reported %v, want exactly /de/privacy", got)
	}
}

func TestMountLegalFailsWhenABuiltPageIsMissing(t *testing.T) {
	dist := fstest.MapFS{
		"de/imprint/index.html": {Data: []byte("x")},
		"de/privacy/index.html": {Data: []byte("x")},
		"en/imprint/index.html": {Data: []byte("x")},
	}
	if err := mountLegal(http.NewServeMux(), dist); err == nil || !strings.Contains(err.Error(), "en/privacy/index.html") {
		t.Fatalf("mountLegal() error = %v, want one naming en/privacy/index.html", err)
	}
}
