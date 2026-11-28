// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostendorf-cloud/burnlink/internal/payload"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		origin  string
		want    string
		wantErr bool
	}{
		{"https origin", "https://burnlink.de", "https://burnlink.de", false},
		{"trailing slash", "https://burnlink.de/", "https://burnlink.de", false},
		{"port", "http://127.0.0.1:8080", "http://127.0.0.1:8080", false},
		{"no scheme", "burnlink.de", "", true},
		{"other scheme", "ftp://burnlink.de", "", true},
		{"no host", "https://", "", true},
		{"user info", "https://user:pw@burnlink.de", "", true},
		{"path", "https://burnlink.de/app", "", true},
		{"query", "https://burnlink.de?x=1", "", true},
		{"fragment", "https://burnlink.de#x", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tt.origin, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New(%q) error = %v, wantErr %v", tt.origin, err, tt.wantErr)
			}
			if err == nil && c.Origin() != tt.want {
				t.Errorf("Origin() = %q, want %q", c.Origin(), tt.want)
			}
		})
	}
}

func TestLink_roundTrip(t *testing.T) {
	t.Parallel()
	c, err := New("https://burnlink.de", nil)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0xab}, 32)
	link := c.Link("abc_DEF-123", key)
	if !strings.HasPrefix(link, "https://burnlink.de/s/abc_DEF-123#") {
		t.Fatalf("link = %q, want the page's /s/<id>#<key> shape", link)
	}
	got, err := ParseLink(link, 32)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if got.Origin != "https://burnlink.de" || got.ID != "abc_DEF-123" || !bytes.Equal(got.Key, key) {
		t.Errorf("ParseLink returned another link than Link built")
	}
}

func TestParseLink_refuses(t *testing.T) {
	t.Parallel()
	key := payload.EncodeBase64URL(bytes.Repeat([]byte{1}, 32))
	short := payload.EncodeBase64URL(bytes.Repeat([]byte{1}, 31))
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no key", "https://burnlink.de/s/abc"},
		{"empty key", "https://burnlink.de/s/abc#"},
		{"short key", "https://burnlink.de/s/abc#" + short},
		{"padded key", "https://burnlink.de/s/abc#" + key + "="},
		{"standard alphabet key", "https://burnlink.de/s/abc#" + strings.Replace(key, "AQE", "+Q/", 1)},
		{"no id", "https://burnlink.de/s/#" + key},
		{"two segments", "https://burnlink.de/s/a/b#" + key},
		{"escaped slash in the id", "https://burnlink.de/s/a%2Fb#" + key},
		{"other path", "https://burnlink.de/r/abc#" + key},
		{"query", "https://burnlink.de/s/abc?x=1#" + key},
		{"other scheme", "ftp://burnlink.de/s/abc#" + key},
		{"user info", "https://u:p@burnlink.de/s/abc#" + key},
		{"not a url", "::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseLink(tt.raw, 32); err == nil {
				t.Errorf("ParseLink(%q) accepted a link it must refuse", tt.raw)
			}
		})
	}
}

func TestParseLink_trimsSurroundingSpace(t *testing.T) {
	t.Parallel()
	key := payload.EncodeBase64URL(bytes.Repeat([]byte{1}, 32))
	if _, err := ParseLink("  https://burnlink.de/s/abc#"+key+"\n", 32); err != nil {
		t.Errorf("a pasted link with a trailing newline must parse: %v", err)
	}
}

func TestClient_Config(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/config" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"maxCiphertextBytes":1048576,"lifetime":{"minSeconds":60,"maxSeconds":604800,"defaultSeconds":86400}}`))
	})
	got, err := c.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	want := Config{
		MaxCiphertextBytes: 1 << 20,
		LifetimeMin:        time.Minute,
		LifetimeMax:        7 * 24 * time.Hour,
		LifetimeDefault:    24 * time.Hour,
	}
	if got != want {
		t.Errorf("Config = %+v, want %+v", got, want)
	}
}

func TestClient_Store(t *testing.T) {
	t.Parallel()
	ciphertext := []byte{0, 1, 2, 0xfe, 0xff}
	tests := []struct {
		name         string
		lifetime     time.Duration
		wantLifetime *int64
	}{
		{"server default", 0, nil},
		{"an hour", time.Hour, ptr(3600)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got struct {
				Ciphertext      string `json:"ciphertext"`
				LifetimeSeconds *int64 `json:"lifetimeSeconds"`
			}
			var contentType, userAgent string
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/secrets" {
					http.NotFound(w, r)
					return
				}
				contentType, userAgent = r.Header.Get("Content-Type"), r.Header.Get("User-Agent")
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"AbCdEfGhIjKlMnOpQrStUv","expiresAt":"2030-01-02T03:04:05Z"}`))
			})
			stored, err := c.Store(context.Background(), ciphertext, tt.lifetime)
			if err != nil {
				t.Fatalf("Store: %v", err)
			}
			if stored.ID != "AbCdEfGhIjKlMnOpQrStUv" || !stored.ExpiresAt.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
				t.Errorf("Store = %+v", stored)
			}
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, the server refuses anything else", contentType)
			}
			if !strings.HasPrefix(userAgent, "burnlink-cli/") {
				t.Errorf("User-Agent = %q", userAgent)
			}
			if got.Ciphertext != payload.EncodeBase64(ciphertext) {
				t.Errorf("ciphertext on the wire = %q, want standard base64", got.Ciphertext)
			}
			switch {
			case tt.wantLifetime == nil && got.LifetimeSeconds != nil:
				t.Errorf("lifetimeSeconds = %d sent, want it left out", *got.LifetimeSeconds)
			case tt.wantLifetime != nil && (got.LifetimeSeconds == nil || *got.LifetimeSeconds != *tt.wantLifetime):
				t.Errorf("lifetimeSeconds = %v, want %d", got.LifetimeSeconds, *tt.wantLifetime)
			}
		})
	}
}

func ptr(v int64) *int64 { return &v }

func TestClient_Store_refusesAnUnusableId(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"", "a/b", "a?b", "a#b"} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "expiresAt": "2030-01-02T03:04:05Z"})
		})
		if _, err := c.Store(context.Background(), []byte{1}, 0); err == nil {
			t.Errorf("Store accepted the id %q", id)
		}
	}
}

func TestClient_Open(t *testing.T) {
	t.Parallel()
	ciphertext := []byte{9, 8, 7, 0xff}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/secrets/abc/open" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ciphertext": payload.EncodeBase64(ciphertext)})
	})
	got, err := c.Open(context.Background(), "abc")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Errorf("Open returned other bytes than the server sent")
	}
}

func TestClient_Open_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   int
		body     string
		wantIs   error
		wantText string
	}{
		{"gone", http.StatusNotFound, `{"error":{"code":"not_found","message":"secret not available"}}`, ErrNotAvailable, ""},
		{"rate limited", http.StatusTooManyRequests, `{}`, ErrRateLimited, ""},
		{"server error", http.StatusInternalServerError, `{"error":{"code":"internal","message":"try later"}}`, nil, "500 internal: try later"},
		{"control characters are not echoed", http.StatusBadRequest, "{\"error\":{\"code\":\"bad\",\"message\":\"a\\u001b[31mred\\nline\"}}", nil, "400 bad: a [31mred line"},
		{"not the error shape", http.StatusBadGateway, `<html>proxy</html>`, nil, "502 unknown: Bad Gateway"},
		{"success with another shape", http.StatusOK, `[]`, nil, "not the JSON"},
		{"ciphertext that is not base64", http.StatusOK, `{"ciphertext":"not base64!"}`, nil, "not base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			_, err := c.Open(context.Background(), "abc")
			if err == nil {
				t.Fatal("Open succeeded, want an error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error = %v, want %v", err, tt.wantIs)
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantText)
			}
		})
	}
}

func TestClient_Open_followsNoRedirect(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(other.Close)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	})
	_, err := c.Store(context.Background(), []byte{1}, 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTemporaryRedirect {
		t.Errorf("error = %v, want an APIError for the redirect", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the redirect target received %d requests, want none", hits.Load())
	}
}

func TestClient_keepsTheCallerClientsRedirectPolicyOff(t *testing.T) {
	t.Parallel()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c, err := New("https://burnlink.de", hc)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.http.CheckRedirect(nil, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse", got)
	}
	if hc.CheckRedirect(nil, nil) != nil {
		t.Errorf("New changed the caller's own client")
	}
}

func TestClient_errorDoesNotRepeatTheId(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := New(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Open(context.Background(), "the-secret-id")
	if err == nil {
		t.Fatal("Open succeeded against a closed server")
	}
	if strings.Contains(err.Error(), "the-secret-id") {
		t.Errorf("error %q repeats the id", err)
	}
}

func TestClient_Open_stopsOnAnOversizedAnswer(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ciphertext":"`))
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for range 100 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	if _, err := c.Open(context.Background(), "abc"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("error = %v, want the size refusal", err)
	}
}
