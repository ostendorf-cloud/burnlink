// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/logging"
	"github.com/ostendorf-cloud/govue/middleware"
	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/buildinfo"
	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/memstore"
)

// The store behind these tests is the in process fake. Its atomicity and
// expiry are proven against a real server in internal/store/redisstore; here
// it only has to behave like the contract says.

const (
	testMax = 16
	b64     = "c2VjcmV0" // "secret"
)

// backend is the in process store plus a count of the writes and the plain
// reads it received. Its Get yields before it answers, so a Take built from
// a Get followed by a delete would leave a window for a second reader.
type backend struct {
	*memstore.Store
	puts *atomic.Int32
	gets *atomic.Int32
}

func (backend) Ping(context.Context) error { return nil }

func (b backend) Get(ctx context.Context, key string) ([]byte, bool, error) {
	b.gets.Add(1)
	value, ok, err := b.Store.Get(ctx, key)
	runtime.Gosched()
	time.Sleep(time.Millisecond)
	return value, ok, err
}

func (b backend) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	b.puts.Add(1)
	return b.Store.SetNX(ctx, key, value, ttl)
}

type harness struct {
	t   *testing.T
	h   *Handler
	mux *http.ServeMux
	// handler is the mux behind the outer middleware main.go puts around it.
	handler http.Handler
	gets    *atomic.Int32
	puts    *atomic.Int32
	vault   *store.Secrets
	now     *time.Time
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mem := memstore.New()
	mem.Now = func() time.Time { return now }
	puts, gets := new(atomic.Int32), new(atomic.Int32)
	vault := store.NewSecrets(backend{mem, puts, gets})
	cfg := Config{
		Vault:           vault,
		MaxBytes:        testMax,
		LifetimeMin:     time.Minute,
		LifetimeMax:     time.Hour,
		LifetimeDefault: 10 * time.Minute,
		// Generous: tests that are not about the limit must not hit it.
		Limiter:  ratelimit.New(10_000, time.Minute, 100),
		ClientIP: clientip.NewResolver(nil),
		Now:      func() time.Time { return now },
		Build:    func() buildinfo.Info { return buildinfo.Info{Version: "v1.2.3", Commit: "abc", GoVersion: "go1.x"} },
	}
	for _, m := range mutate {
		m(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return &harness{t: t, h: h, mux: mux, handler: NoStoreOnAPI(mux), puts: puts, gets: gets, vault: vault, now: &now}
}

type reqOpt func(*http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func remote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }

// do sends a request. A body gets the JSON content type unless an option
// replaces it.
func (hn *harness) do(method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	hn.t.Helper()
	return serve(hn.t, hn.handler, method, path, body, opts...)
}

func serve(t *testing.T, h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// put stores b64 and returns the issued id.
func (hn *harness) put(body string) string {
	hn.t.Helper()
	rec := hn.do(http.MethodPost, "/api/v1/secrets", body)
	if rec.Code != http.StatusCreated {
		hn.t.Fatalf("store = %d, body %s", rec.Code, rec.Body)
	}
	var out storeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		hn.t.Fatalf("store body %s: %v", rec.Body, err)
	}
	return out.ID
}

func ciphertextBody(n int) string {
	return fmt.Sprintf(`{"ciphertext":%q}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, n)))
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Error struct{ Code string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q is not the error shape: %v", rec.Body, err)
	}
	return out.Error.Code
}

func TestStore(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		body     string
		opts     []reqOpt
		want     int
		wantCode string
	}{
		{name: "default lifetime", body: `{"ciphertext":"` + b64 + `"}`, want: 201},
		{name: "explicit lifetime", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":120}`, want: 201},
		{
			name: "charset on the content type", body: `{"ciphertext":"` + b64 + `"}`,
			opts: []reqOpt{header("Content-Type", "application/json; charset=utf-8")}, want: 201,
		},
		{name: "exactly the size limit", body: ciphertextBody(testMax), want: 201},
		{name: "one byte over the size limit", body: ciphertextBody(testMax + 1), want: 413, wantCode: "request_too_large"},
		{name: "far over the size limit", body: ciphertextBody(100_000), want: 413, wantCode: "request_too_large"},
		{name: "lifetime at the minimum", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":60}`, want: 201},
		{name: "lifetime at the maximum", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":3600}`, want: 201},
		{name: "lifetime below the minimum", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":59}`, want: 400, wantCode: "invalid_argument"},
		{name: "lifetime above the maximum", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":3601}`, want: 400, wantCode: "invalid_argument"},
		{name: "lifetime that would overflow", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":9223372036854775807}`, want: 400, wantCode: "invalid_argument"},
		{name: "negative lifetime", body: `{"ciphertext":"` + b64 + `","lifetimeSeconds":-1}`, want: 400, wantCode: "invalid_argument"},
		{name: "empty ciphertext", body: `{"ciphertext":""}`, want: 400, wantCode: "invalid_argument"},
		{name: "missing ciphertext", body: `{}`, want: 400, wantCode: "invalid_argument"},
		{name: "not base64", body: `{"ciphertext":"!!!"}`, want: 400, wantCode: "invalid_argument"},
		{name: "url safe base64 is not standard", body: `{"ciphertext":"_-8="}`, want: 400, wantCode: "invalid_argument"},
		{name: "unknown field", body: `{"ciphertext":"` + b64 + `","ttl":5}`, want: 400, wantCode: "invalid_argument"},
		{name: "not json", body: `ciphertext`, want: 400, wantCode: "invalid_argument"},
		{name: "empty body", body: ``, want: 400, wantCode: "invalid_argument"},
		{name: "two json values", body: `{"ciphertext":"` + b64 + `"}{}`, want: 400, wantCode: "invalid_argument"},
		{
			name: "text plain", body: `{"ciphertext":"` + b64 + `"}`,
			opts: []reqOpt{header("Content-Type", "text/plain")}, want: 415, wantCode: "unsupported_media_type",
		},
		{
			name: "form encoded", body: `ciphertext=` + b64,
			opts: []reqOpt{header("Content-Type", "application/x-www-form-urlencoded")}, want: 415, wantCode: "unsupported_media_type",
		},
		{
			name: "missing content type", body: `{"ciphertext":"` + b64 + `"}`,
			opts: []reqOpt{func(r *http.Request) { r.Header.Del("Content-Type") }}, want: 415, wantCode: "unsupported_media_type",
		},
		{
			name: "json lookalike", body: `{"ciphertext":"` + b64 + `"}`,
			opts: []reqOpt{header("Content-Type", "application/jsonp")}, want: 415, wantCode: "unsupported_media_type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hn := newHarness(t)
			rec := hn.do(http.MethodPost, "/api/v1/secrets", tc.body, tc.opts...)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tc.want, rec.Body)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if tc.wantCode != "" {
				if got := errorCode(t, rec); got != tc.wantCode {
					t.Errorf("error code = %q, want %q", got, tc.wantCode)
				}
				if hn.puts.Load() != 0 {
					t.Errorf("a refused request stored %d keys, want 0", hn.puts.Load())
				}
			}
		})
	}
}

func TestStoreAnswersWithAnIDAndTheExpiry(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	rec := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`","lifetimeSeconds":120}`)
	var out storeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	if !validID(out.ID) {
		t.Errorf("id %q is not a valid id", out.ID)
	}
	if want := hn.now.Add(2 * time.Minute); !out.ExpiresAt.Equal(want) {
		t.Errorf("expiresAt = %v, want %v", out.ExpiresAt, want)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestStoreAppliesTheLifetime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		advance time.Duration
		want    int
	}{
		{"default lifetime still valid", `{"ciphertext":"` + b64 + `"}`, 9 * time.Minute, 200},
		{"default lifetime elapsed", `{"ciphertext":"` + b64 + `"}`, 11 * time.Minute, 404},
		{"explicit lifetime still valid", `{"ciphertext":"` + b64 + `","lifetimeSeconds":120}`, time.Minute, 200},
		{"explicit lifetime elapsed", `{"ciphertext":"` + b64 + `","lifetimeSeconds":120}`, 3 * time.Minute, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hn := newHarness(t)
			id := hn.put(tc.body)
			*hn.now = hn.now.Add(tc.advance)
			if got := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}").Code; got != tc.want {
				t.Errorf("open after %v = %d, want %d", tc.advance, got, tc.want)
			}
		})
	}
}

// countingReader counts how much of an oversized body the server read.
type countingReader struct {
	n    atomic.Int64
	left int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), c.left)
	for i := range p[:n] {
		// Valid JSON for as long as it goes: an open string of 'a'.
		if c.n.Load()+int64(i) < int64(len(`{"ciphertext":"`)) {
			p[i] = `{"ciphertext":"`[c.n.Load()+int64(i)]
		} else {
			p[i] = 'a'
		}
	}
	c.left -= n
	c.n.Add(n)
	return int(n), nil
}

func TestStoreStopsReadingAnOversizedBody(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	body := &countingReader{left: 50 << 20}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/secrets", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	hn.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if read := body.n.Load(); read > 64<<10 {
		t.Errorf("read %d bytes of a 50 MiB body, want it to stop near the limit", read)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)

	rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d, body %s", rec.Code, rec.Body)
	}
	var out openResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Ciphertext != b64 {
		t.Errorf("body %s, want ciphertext %q (%v)", rec.Body, b64, err)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if again := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}"); again.Code != http.StatusNotFound {
		t.Errorf("second open = %d, want 404", again.Code)
	}
}

func TestOpenRequiresAJSONContentType(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)
	path := "/api/v1/secrets/" + id + "/open"

	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
		rec := hn.do(http.MethodPost, path, "{}", func(r *http.Request) {
			if ct == "" {
				r.Header.Del("Content-Type")
			} else {
				r.Header.Set("Content-Type", ct)
			}
		})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("open with %q = %d, want 415", ct, rec.Code)
		}
	}
	// None of the refusals consumed the secret.
	if rec := hn.do(http.MethodPost, path, "{}"); rec.Code != http.StatusOK {
		t.Errorf("open after the refusals = %d, want 200", rec.Code)
	}
}

func TestCheckDoesNotConsume(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)

	for i := range 3 {
		rec := hn.do(http.MethodHead, "/api/v1/secrets/"+id, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD #%d = %d, want 200", i, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD #%d carries a body %q", i, rec.Body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("HEAD Cache-Control = %q, want no-store", got)
		}
	}
	rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open after HEAD = %d, want 200: HEAD consumed the secret", rec.Code)
	}
	if got := hn.do(http.MethodHead, "/api/v1/secrets/"+id, "").Code; got != http.StatusNotFound {
		t.Errorf("HEAD after open = %d, want 404", got)
	}
}

// TestConcurrentOpensServeExactlyOne checks what the handler layer owns: one
// open is one atomic GETDEL and nothing else. The atomicity itself is the
// store's property, proven against a real server in internal/store/redisstore.
// The fake's plain Get yields, so a read then delete built from Get would
// both open a window for a second reader and show up in the Get count.
func TestConcurrentOpensServeExactlyOne(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)
	getsBefore := hn.gets.Load()

	const readers = 64
	var served, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		wg.Go(func() {
			<-start
			switch hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}").Code {
			case http.StatusOK:
				served.Add(1)
			case http.StatusNotFound:
				refused.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if served.Load() != 1 || refused.Load() != readers-1 {
		t.Errorf("served %d, refused %d, want 1 and %d", served.Load(), refused.Load(), readers-1)
	}
	if got := hn.gets.Load() - getsBefore; got != 0 {
		t.Errorf("opening made %d plain reads, want 0: a reveal must be one GETDEL", got)
	}
}

// refusalCases are every link the service will not serve. The ids are built
// per harness, because the issued ones differ.
func refusalIDs(t *testing.T, hn *harness) map[string]string {
	t.Helper()

	opened := hn.put(`{"ciphertext":"` + b64 + `"}`)
	if got := hn.do(http.MethodPost, "/api/v1/secrets/"+opened+"/open", "{}").Code; got != http.StatusOK {
		t.Fatalf("setup open = %d", got)
	}
	expired := hn.put(`{"ciphertext":"` + b64 + `","lifetimeSeconds":60}`)
	live := hn.put(`{"ciphertext":"` + b64 + `"}`)
	*hn.now = hn.now.Add(2 * time.Minute) // expires `expired`, not `live`

	// A non canonical spelling of a live id: same length and alphabet, with
	// the last character changed to one that carries stray trailing bits.
	nonCanonical := live[:idLen-1] + "B"
	if live[idLen-1] == 'B' {
		nonCanonical = live[:idLen-1] + "C"
	}

	return map[string]string{
		"unknown":                    "AAAAAAAAAAAAAAAAAAAAAQ",
		"unknown, other":             "zzzzzzzzzzzzzzzzzzzzzw",
		"already opened":             opened,
		"expired":                    expired,
		"empty":                      "",
		"too short":                  "abc",
		"one short":                  strings.Repeat("A", idLen-1),
		"one long":                   strings.Repeat("A", idLen+1),
		"far too long":               strings.Repeat("A", 5000),
		"bad alphabet":               strings.Repeat("!", idLen),
		"standard alphabet":          strings.Repeat("+", idLen-1) + "w",
		"padded":                     strings.Repeat("A", idLen-2) + "==",
		"unicode":                    "%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC",
		"unicode of the right width": strings.Repeat("%C3%A4", idLen),
		"null byte":                  "AAAAAAAAAAAAAAAAAAAA%00A",
		"escaped slash":              "a%2Fb",
		"space":                      "AAAAAAAAAAAA%20AAAAAAAAA",
		"non canonical trailing bit": nonCanonical,
		"other keyspace":             "requestlink:abc",
		"the dummy id":               dummyID,
	}
}

type snapshot struct {
	status int
	header http.Header
	body   string
}

func snap(rec *httptest.ResponseRecorder) snapshot {
	return snapshot{rec.Code, rec.Header().Clone(), rec.Body.String()}
}

// TestRefusalsAreIndistinguishable is the security property of the service:
// unknown, expired, already opened and malformed ids get one answer, equal in
// status, headers and body, byte for byte.
func TestRefusalsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	ids := refusalIDs(t, hn)

	type route struct {
		name   string
		method string
		path   func(id string) string
		body   string
	}
	routes := []route{
		{"check", http.MethodHead, func(id string) string { return "/api/v1/secrets/" + id }, ""},
		{"open", http.MethodPost, func(id string) string { return "/api/v1/secrets/" + id + "/open" }, "{}"},
		{"get", http.MethodGet, func(id string) string { return "/api/v1/secrets/" + id }, ""},
		{"delete", http.MethodDelete, func(id string) string { return "/api/v1/secrets/" + id }, ""},
	}

	// The reference is the plainest refusal, an id that never existed.
	var reference snapshot
	for _, r := range routes {
		var first snapshot
		for cause, id := range ids {
			if id == "" && r.name == "open" {
				// net/http's mux redirects //open to a clean path before any
				// handler runs; that is the same redirect for every empty
				// id and carries no id at all.
				continue
			}
			path := r.path(id)
			if id == "" {
				path = "/api/v1/secrets/"
			}
			got := snap(hn.do(r.method, path, r.body))
			if got.status != http.StatusNotFound {
				t.Errorf("%s %s: status = %d, want 404, body %q", r.name, cause, got.status, got.body)
			}
			if got.body == "" {
				t.Errorf("%s %s: empty body", r.name, cause)
			}
			if first.status == 0 {
				first = got
				continue
			}
			assertSame(t, r.name+" "+cause, first, got)
		}
		if reference.status == 0 {
			reference = first
		}
		// Every method and route refuses with the very same body.
		if first.body != reference.body || first.status != reference.status {
			t.Errorf("%s refusal %+v differs from %+v", r.name, first, reference)
		}
	}

	// Nothing about the refusal says anything about the id.
	for cause, id := range ids {
		if id != "" && strings.Contains(reference.body, id) {
			t.Errorf("refusal body contains the id of case %q", cause)
		}
	}
}

func assertSame(t *testing.T, name string, want, got snapshot) {
	t.Helper()
	if got.status != want.status {
		t.Errorf("%s: status = %d, want %d", name, got.status, want.status)
	}
	if got.body != want.body {
		t.Errorf("%s: body = %q, want %q", name, got.body, want.body)
	}
	if fmt.Sprint(got.header) != fmt.Sprint(want.header) {
		t.Errorf("%s: headers = %v, want %v", name, got.header, want.header)
	}
}

// TestRefusalsAreIndistinguishableOnTheWire repeats the comparison through a
// real server and the request id middleware, so what is compared is what a
// client receives: Content-Length, no ETag and no per request value other
// than the request id header itself.
func TestRefusalsAreIndistinguishableOnTheWire(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	ids := refusalIDs(t, hn)
	chain := middleware.Chain(hn.handler, middleware.RequestID(testLogger()))
	srv := httptest.NewServer(chain)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	do := func(method, id string) (int, string, string) {
		path := "/api/v1/secrets/" + id
		var body io.Reader
		if method == http.MethodPost {
			path += "/open"
			body = strings.NewReader("{}")
		}
		if id == "" {
			path = "/api/v1/secrets/"
		}
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, body)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		resp.Header.Del("Date")
		resp.Header.Del(middleware.RequestIDHeader)
		return resp.StatusCode, fmt.Sprint(resp.Header, " length=", resp.ContentLength), string(raw)
	}

	for _, method := range []string{http.MethodHead, http.MethodPost} {
		var wantStatus int
		var wantHeader, wantBody string
		for cause, id := range ids {
			if id == "" && method == http.MethodPost {
				continue
			}
			status, hdr, body := do(method, id)
			if wantStatus == 0 {
				wantStatus, wantHeader, wantBody = status, hdr, body
				if status != http.StatusNotFound {
					t.Fatalf("%s %s: status %d", method, cause, status)
				}
				if strings.Contains(strings.ToLower(hdr), "etag") {
					t.Errorf("refusal carries an ETag: %s", hdr)
				}
				continue
			}
			if status != wantStatus || hdr != wantHeader || (method == http.MethodPost && body != wantBody) {
				t.Errorf("%s %s differs: %d %s %q, want %d %s %q", method, cause, status, hdr, body, wantStatus, wantHeader, wantBody)
			}
		}
	}
}

func TestRefusalBodyHasNoRequestID(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	chain := middleware.Chain(hn.handler, middleware.RequestID(testLogger()))
	a := serve(t, chain, http.MethodPost, "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA/open", "{}")
	b := serve(t, chain, http.MethodPost, "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAQ/open", "{}")
	if a.Header().Get(middleware.RequestIDHeader) == b.Header().Get(middleware.RequestIDHeader) {
		t.Fatal("the request ids are equal, the test proves nothing")
	}
	if a.Body.String() != b.Body.String() {
		t.Errorf("refusal bodies differ per request: %q and %q", a.Body, b.Body)
	}
	if strings.Contains(a.Body.String(), "request_id") {
		t.Errorf("refusal body carries a request id: %q", a.Body)
	}
}

func TestMalformedIDsDoTheSameStoreWork(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"AAAAAAAAAAAAAAAAAAAAAQ", "abc"} {
		for _, tc := range []struct {
			name, method, suffix, body string
		}{{"check", http.MethodHead, "", ""}, {"open", http.MethodPost, "/open", "{}"}} {
			rec := &recordingVault{}
			hn := newHarness(t, func(c *Config) { c.Vault = rec })
			hn.do(tc.method, "/api/v1/secrets/"+id+tc.suffix, tc.body)
			if rec.calls() != 1 {
				t.Errorf("%s with %q: %d store calls, want exactly 1 for a well formed and a malformed id alike", tc.name, id, rec.calls())
			}
		}
	}
}

// recordingVault counts calls and asks the store about nothing.
type recordingVault struct {
	mu   sync.Mutex
	asks []string
}

func (v *recordingVault) record(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.asks = append(v.asks, id)
}

func (v *recordingVault) calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.asks)
}

func (*recordingVault) Put(context.Context, string, []byte, time.Duration) error { return nil }
func (v *recordingVault) Take(_ context.Context, id string) ([]byte, error) {
	v.record(id)
	return nil, store.ErrNotFound
}

func (v *recordingVault) Exists(_ context.Context, id string) (bool, error) {
	v.record(id)
	return false, nil
}

func TestMalformedIDNeverReachesTheStore(t *testing.T) {
	t.Parallel()

	rec := &recordingVault{}
	hn := newHarness(t, func(c *Config) { c.Vault = rec })
	for _, id := range []string{"abc", "requestlink:abc", strings.Repeat("A", 5000), "%E2%82%AC"} {
		hn.do(http.MethodHead, "/api/v1/secrets/"+id, "")
		hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	}
	for _, asked := range rec.asks {
		if asked != dummyID {
			t.Errorf("the store was asked about %q, want only the dummy id", asked)
		}
	}
}

// failingVault fails every call, standing for an unreachable store.
type failingVault struct{}

func (failingVault) Put(context.Context, string, []byte, time.Duration) error {
	return errors.New("dial tcp: boom")
}

func (failingVault) Take(context.Context, string) ([]byte, error) {
	return nil, errors.New("dial tcp: boom")
}

func (failingVault) Exists(context.Context, string) (bool, error) {
	return false, errors.New("dial tcp: boom")
}

func TestStoreOutageIsAnErrorNotARefusal(t *testing.T) {
	t.Parallel()

	hn := newHarness(t, func(c *Config) { c.Vault = failingVault{} })
	id := "AAAAAAAAAAAAAAAAAAAAAQ"
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/secrets", `{"ciphertext":"` + b64 + `"}`},
		{http.MethodHead, "/api/v1/secrets/" + id, ""},
		{http.MethodPost, "/api/v1/secrets/" + id + "/open", "{}"},
	} {
		rec := hn.do(tc.method, tc.path, tc.body)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s = %d, want 500", tc.method, tc.path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "boom") || strings.Contains(rec.Body.String(), "dial") {
			t.Errorf("%s: the cause reached the client: %s", tc.path, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", tc.path, rec.Header().Get("Cache-Control"))
		}
	}
}

// collidingVault answers every write with ErrExists and counts the attempts.
type collidingVault struct {
	recordingVault
	puts atomic.Int32
}

func (v *collidingVault) Put(context.Context, string, []byte, time.Duration) error {
	v.puts.Add(1)
	return store.ErrExists
}

// TestStoreDoesNotRetryAnIDCollision: a collision of 128 random bits is a
// bug to surface as a 500, not a condition to retry around.
func TestStoreDoesNotRetryAnIDCollision(t *testing.T) {
	t.Parallel()

	v := &collidingVault{}
	hn := newHarness(t, func(c *Config) { c.Vault = v })
	rec := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if got := v.puts.Load(); got != 1 {
		t.Errorf("Put was called %d times, want exactly 1", got)
	}
	if strings.Contains(rec.Body.String(), "exists") {
		t.Errorf("the cause reached the client: %s", rec.Body)
	}
}

// TestMuxRedirectsAreNoStore: the mux answers a path it has to clean with a
// redirect before any route runs. It still carries no-store, and what it says
// does not depend on the secret behind the path.
func TestMuxRedirectsAreNoStore(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	live := hn.put(`{"ciphertext":"` + b64 + `"}`)
	for _, path := range []string{
		"/api/v1/secrets//open",
		"/api//v1/config",
		"/api/./v1/config",
		"/api/v1/../v1/config",
		"//api/v1/config",
		"/api/v1/secrets/" + live + "/../" + live,
	} {
		rec := hn.do(http.MethodGet, path, "")
		if rec.Code < 300 || rec.Code > 399 {
			t.Errorf("GET %s = %d, want a redirect", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s (%d): Cache-Control = %q, want no-store", path, rec.Code, got)
		}
	}

	// The same cleaned path redirects to the same place whatever it hides.
	a := snap(hn.do(http.MethodPost, "/api/v1/secrets//open", "{}"))
	b := snap(hn.do(http.MethodPost, "/api/v1/secrets//open", "{}", header("X-Whatever", "1")))
	assertSame(t, "redirect", a, b)
}

func TestRateLimit(t *testing.T) {
	t.Parallel()

	limited := func(c *Config) { c.Limiter = ratelimit.New(2, time.Hour, 100) }
	id := "AAAAAAAAAAAAAAAAAAAAAQ"
	cases := []struct {
		name, method, path, body string
	}{
		{"store", http.MethodPost, "/api/v1/secrets", `{"ciphertext":"` + b64 + `"}`},
		{"check", http.MethodHead, "/api/v1/secrets/" + id, ""},
		{"open", http.MethodPost, "/api/v1/secrets/" + id + "/open", "{}"},
		{"every other secrets path", http.MethodGet, "/api/v1/secrets/" + id, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hn := newHarness(t, limited)
			for i := range 2 {
				if got := hn.do(tc.method, tc.path, tc.body).Code; got == http.StatusTooManyRequests {
					t.Fatalf("request %d was limited inside the burst", i+1)
				}
			}
			rec := hn.do(tc.method, tc.path, tc.body)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("third request = %d, want 429", rec.Code)
			}
			if got := errorCode(t, rec); got != "too_many_requests" {
				t.Errorf("error code = %q", got)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("429 Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestRateLimitSharesOneBudgetPerAddressAndLeavesConfigAlone(t *testing.T) {
	t.Parallel()

	hn := newHarness(t, func(c *Config) { c.Limiter = ratelimit.New(1, time.Hour, 100) })
	one := remote("192.0.2.1:1000")
	two := remote("192.0.2.2:1000")

	if got := hn.do(http.MethodHead, "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAQ", "", one).Code; got != 404 {
		t.Fatalf("first = %d", got)
	}
	if got := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`"}`, one).Code; got != 429 {
		t.Errorf("a second route from the same address = %d, want 429: one budget per address", got)
	}
	if got := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`"}`, two).Code; got != 201 {
		t.Errorf("another address = %d, want 201", got)
	}
	for range 5 {
		if got := hn.do(http.MethodGet, "/api/v1/config", "", one).Code; got != 200 {
			t.Errorf("config = %d, want 200: the page reads it on every load", got)
		}
	}
}

func TestRateLimitUsesTheResolvedClientAddress(t *testing.T) {
	t.Parallel()

	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	hn := newHarness(t, func(c *Config) {
		c.Limiter = ratelimit.New(1, time.Hour, 100)
		c.ClientIP = clientip.NewResolver(proxies)
	})
	path := "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAQ"
	viaProxy := func(xff string) []reqOpt {
		return []reqOpt{remote("10.1.2.3:5000"), header("X-Forwarded-For", xff)}
	}

	if got := hn.do(http.MethodHead, path, "", viaProxy("198.51.100.1")...).Code; got != 404 {
		t.Fatalf("client A first = %d", got)
	}
	if got := hn.do(http.MethodHead, path, "", viaProxy("198.51.100.1")...).Code; got != 429 {
		t.Errorf("client A second = %d, want 429", got)
	}
	if got := hn.do(http.MethodHead, path, "", viaProxy("198.51.100.2")...).Code; got != 404 {
		t.Errorf("client B behind the same proxy = %d, want its own budget", got)
	}
	// A forged entry left of the one the proxy appended decides nothing.
	if got := hn.do(http.MethodHead, path, "", viaProxy("203.0.113.9, 198.51.100.1")...).Code; got != 429 {
		t.Errorf("client A with a forged prefix = %d, want 429", got)
	}
}

func TestRateLimitIgnoresForwardedForFromAnUntrustedPeer(t *testing.T) {
	t.Parallel()

	hn := newHarness(t, func(c *Config) {
		c.Limiter = ratelimit.New(1, time.Hour, 100)
		c.ClientIP = clientip.NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	})
	path := "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAQ"
	peer := remote("192.0.2.50:1")

	if got := hn.do(http.MethodHead, path, "", peer, header("X-Forwarded-For", "198.51.100.1")).Code; got != 404 {
		t.Fatalf("first = %d", got)
	}
	if got := hn.do(http.MethodHead, path, "", peer, header("X-Forwarded-For", "198.51.100.2")).Code; got != 429 {
		t.Errorf("a changed X-Forwarded-For from an untrusted peer = %d, want 429: the header must not buy a fresh budget", got)
	}
}

func TestCrossSiteRequestsAreRefused(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"fetch metadata cross-site", []reqOpt{header("Sec-Fetch-Site", "cross-site")}, 403},
		{"fetch metadata same-site", []reqOpt{header("Sec-Fetch-Site", "same-site")}, 403},
		{"fetch metadata same-origin", []reqOpt{header("Sec-Fetch-Site", "same-origin")}, 201},
		{"fetch metadata none", []reqOpt{header("Sec-Fetch-Site", "none")}, 201},
		{"foreign Origin without fetch metadata", []reqOpt{header("Origin", "https://evil.example")}, 403},
		{"Origin null without fetch metadata", []reqOpt{header("Origin", "null")}, 403},
		{"Origin null with same-origin fetch metadata", []reqOpt{header("Origin", "null"), header("Sec-Fetch-Site", "same-origin")}, 201},
		{"own Origin without fetch metadata", []reqOpt{header("Origin", "http://example.com")}, 201},
		{"no browser signal at all", nil, 201},
	}
	for _, tc := range cases {
		t.Run("store "+tc.name, func(t *testing.T) {
			t.Parallel()

			hn := newHarness(t)
			rec := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`"}`, tc.opts...)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == 403 {
				if got := errorCode(t, rec); got != "permission_denied" {
					t.Errorf("error code = %q", got)
				}
				if hn.puts.Load() != 0 {
					t.Error("a cross site store wrote a key")
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
				}
			}
		})
		t.Run("open "+tc.name, func(t *testing.T) {
			t.Parallel()

			hn := newHarness(t)
			id := hn.put(`{"ciphertext":"` + b64 + `"}`)
			want := tc.want
			if want == 201 {
				want = 200
			}
			rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}", tc.opts...)
			if rec.Code != want {
				t.Fatalf("status = %d, want %d", rec.Code, want)
			}
			if want == 403 && hn.do(http.MethodHead, "/api/v1/secrets/"+id, "").Code != 200 {
				t.Error("a refused cross site open consumed the secret")
			}
		})
	}
}

func TestSafeMethodsAreNotRefusedAsCrossSite(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)
	cross := header("Sec-Fetch-Site", "cross-site")
	if got := hn.do(http.MethodHead, "/api/v1/secrets/"+id, "", cross).Code; got != 200 {
		t.Errorf("HEAD = %d, want 200: it reads nothing it could change", got)
	}
	if got := hn.do(http.MethodGet, "/api/v1/config", "", cross).Code; got != 200 {
		t.Errorf("config = %d, want 200", got)
	}
}

func TestConfigAndVersion(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)

	rec := hn.do(http.MethodGet, "/api/v1/config", "")
	if rec.Code != 200 {
		t.Fatalf("config = %d", rec.Code)
	}
	want := `{"maxCiphertextBytes":16,"lifetime":{"minSeconds":60,"maxSeconds":3600,"defaultSeconds":600}}`
	if rec.Body.String() != want {
		t.Errorf("config body = %s, want %s", rec.Body, want)
	}

	rec = hn.do(http.MethodGet, "/api/v1/version", "")
	if rec.Code != 200 {
		t.Fatalf("version = %d", rec.Code)
	}
	want = `{"version":"v1.2.3","commit":"abc","goVersion":"go1.x"}`
	if rec.Body.String() != want {
		t.Errorf("version body = %s, want %s", rec.Body, want)
	}
	for _, path := range []string{"/api/v1/config", "/api/v1/version"} {
		if got := hn.do(http.MethodGet, path, "").Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control = %q", path, got)
		}
		if got := hn.do(http.MethodPost, path, "{}").Code; got != 404 {
			t.Errorf("POST %s = %d, want 404", path, got)
		}
	}
}

func TestUnknownAPIPathAnswersJSON(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	for _, path := range []string{"/api/", "/api/v1/nothing", "/api/v1/request-links/x", "/api/v1/secrets"} {
		rec := hn.do(http.MethodGet, path, "")
		if rec.Code != 404 || errorCode(t, rec) != "not_found" {
			t.Errorf("GET %s = %d %s", path, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s Cache-Control = %q", path, rec.Header().Get("Cache-Control"))
		}
	}
}

// TestEveryAnswerIsNoStore sweeps every kind of answer the API gives.
func TestEveryAnswerIsNoStore(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)
	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/secrets", `{"ciphertext":"` + b64 + `"}`},
		{http.MethodPost, "/api/v1/secrets", `nope`},
		{http.MethodPost, "/api/v1/secrets", ciphertextBody(testMax + 1)},
		{http.MethodHead, "/api/v1/secrets/" + id, ""},
		{http.MethodHead, "/api/v1/secrets/bad", ""},
		{http.MethodPost, "/api/v1/secrets/" + id + "/open", "{}"},
		{http.MethodPost, "/api/v1/secrets/" + id + "/open", "{}"},
		{http.MethodGet, "/api/v1/secrets/" + id, ""},
		{http.MethodGet, "/api/v1/config", ""},
		{http.MethodGet, "/api/v1/version", ""},
		{http.MethodGet, "/api/v1/unknown", ""},
	}
	for _, tc := range cases {
		rec := hn.do(tc.method, tc.path, tc.body)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s (%d): Cache-Control = %q, want no-store", tc.method, tc.path, rec.Code, got)
		}
	}
}

func testLogger() *slog.Logger { return newTestLogger(io.Discard) }

// newTestLogger is govue's own JSON logger at debug level, the most verbose.
func newTestLogger(w io.Writer) *slog.Logger { return logging.New(w, slog.LevelDebug) }

// lockedBuffer is a buffer the server goroutines may write concurrently.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNeitherIDNorSecretReachesTheLog runs the whole flow through the access
// log at debug level, the most verbose one, and looks for the id and the
// ciphertext in everything written.
func TestNeitherIDNorSecretReachesTheLog(t *testing.T) {
	t.Parallel()

	var buf lockedBuffer
	logger := newTestLogger(&buf)
	hn := newHarness(t)
	accessLog := middleware.AccessLog{ClientIP: clientip.NewResolver(nil)}
	chain := middleware.Chain(hn.handler, middleware.RequestID(logger), accessLog.Middleware)

	create := serve(t, chain, http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+b64+`"}`)
	var out storeResponse
	if err := json.Unmarshal(create.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %s: %v", create.Body, err)
	}
	const unknown = "AAAAAAAAAAAAAAAAAAAAAQ"
	serve(t, chain, http.MethodHead, "/api/v1/secrets/"+out.ID, "")
	serve(t, chain, http.MethodPost, "/api/v1/secrets/"+out.ID+"/open", "{}")
	serve(t, chain, http.MethodPost, "/api/v1/secrets/"+out.ID+"/open", "{}")
	serve(t, chain, http.MethodHead, "/api/v1/secrets/"+unknown, "")
	serve(t, chain, http.MethodPost, "/api/v1/secrets/"+unknown+"/open", "{}", header("Sec-Fetch-Site", "cross-site"))

	logs := buf.String()
	if !strings.Contains(logs, "/api/v1/secrets/{id}/open") {
		t.Fatalf("the access log has no route pattern, the test proves nothing:\n%s", logs)
	}
	for _, secret := range []string{out.ID, unknown, b64} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains %q:\n%s", secret, logs)
		}
	}
}

func TestNewID(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for range 2000 {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID() error = %v", err)
		}
		if len(id) != 22 || !validID(id) {
			t.Fatalf("NewID() = %q, want 22 valid characters", id)
		}
		raw, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(raw) < 16 {
			t.Fatalf("id %q carries %d bytes of entropy, want at least 16 (128 bits)", id, len(raw))
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestValidID(t *testing.T) {
	t.Parallel()

	good, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id   string
		want bool
	}{
		{good, true},
		{dummyID, true},
		{"", false},
		{good[:21], false},
		{good + "A", false},
		{good[:21] + "=", false},
		{good[:21] + "!", false},
		{good[:20] + "+/", false},
		{strings.Repeat("\u00e4", 22), false},
		{good[:21] + "B", false}, // stray trailing bits
	}
	for _, tc := range cases {
		if got := validID(tc.id); got != tc.want {
			t.Errorf("validID(%q) = %t, want %t", tc.id, got, tc.want)
		}
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	t.Parallel()

	good := func() Config {
		return Config{
			Vault: failingVault{}, MaxBytes: 1, LifetimeMin: time.Second, LifetimeMax: time.Hour, LifetimeDefault: time.Minute,
			Limiter: ratelimit.New(1, time.Second, 1), ClientIP: clientip.NewResolver(nil),
		}
	}
	if _, err := New(good()); err != nil {
		t.Fatalf("New(good) error = %v", err)
	}
	breakers := map[string]func(*Config){
		"no vault":         func(c *Config) { c.Vault = nil },
		"no limiter":       func(c *Config) { c.Limiter = nil },
		"no resolver":      func(c *Config) { c.ClientIP = nil },
		"no size":          func(c *Config) { c.MaxBytes = 0 },
		"min above max":    func(c *Config) { c.LifetimeMin = 2 * time.Hour },
		"default above":    func(c *Config) { c.LifetimeDefault = 2 * time.Hour },
		"default below":    func(c *Config) { c.LifetimeMin, c.LifetimeDefault = time.Minute, time.Second },
		"sub second floor": func(c *Config) { c.LifetimeMin = time.Millisecond },
	}
	for name, mutate := range breakers {
		cfg := good()
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() error = nil", name)
		}
	}
}
