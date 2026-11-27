// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package requestlink

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/memstore"
)

// newTestHandler returns a Handler over a fresh in-memory store, a clock
// callers can move by hand, and limits small enough for a test to reach
// their boundary without generating megabytes of traffic.
func newTestHandler(t *testing.T) (*Handler, *time.Time) {
	t.Helper()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := NewHandler(memstore.New(), nil)
	h.Now = func() time.Time { return now }
	h.Lifetime = time.Hour
	h.MaxSubmissionBytes = 16
	h.MaxConcurrentSubmissions = 2
	// Generous on purpose: most of these tests submit more than once from
	// the same resolved test address and are not themselves testing the
	// rate limit. TestSubmitIsRateLimitedPerLinkAndAddress installs its own
	// tight limiter instead of relying on this default.
	h.SubmitLimiter = ratelimit.New(100, time.Minute, 100)
	h.LookupLimiter = ratelimit.New(100, time.Minute, 100)
	h.CreateLimiter = ratelimit.New(100, time.Minute, 100)
	return h, &now
}

func newMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// ownerAuth returns a fixed owner auth value and the base64 SHA-256 digest
// of it a create request carries, standing in for what a real browser
// derives from its private key; see docs/adr/0003.
func ownerAuth(seed byte) (value, hash []byte) {
	value = bytes.Repeat([]byte{seed}, ownerAuthBytes)
	sum := sha256.Sum256(value)
	return value, sum[:]
}

// doJSON POSTs body as JSON to path and returns the recorded response.
// Every endpoint this handler registers takes POST, so the method is not a
// parameter.
func doJSON(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), "POST", path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func createLink(t *testing.T, mux *http.ServeMux, ownerAuthHash []byte) createResponse {
	t.Helper()
	rec := doJSON(t, mux, "/api/v1/request-links", createRequest{
		OwnerAuthHash: base64.StdEncoding.EncodeToString(ownerAuthHash),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusCreated)
	}
	var resp createResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return resp
}

func TestCreateReturnsANewIDAndTheConfiguredLimits(t *testing.T) {
	t.Parallel()

	h, now := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)

	link := createLink(t, mux, authHash)

	if link.ID == "" {
		t.Error("ID is empty, want a generated id")
	}
	if link.MaxSubmissionBytes != h.MaxSubmissionBytes {
		t.Errorf("MaxSubmissionBytes = %d, want %d", link.MaxSubmissionBytes, h.MaxSubmissionBytes)
	}
	if link.MaxConcurrentSubmissions != h.MaxConcurrentSubmissions {
		t.Errorf("MaxConcurrentSubmissions = %d, want %d", link.MaxConcurrentSubmissions, h.MaxConcurrentSubmissions)
	}
	if !link.ExpiresAt.Equal(now.Add(h.Lifetime)) {
		t.Errorf("ExpiresAt = %v, want %v", link.ExpiresAt, now.Add(h.Lifetime))
	}
}

func TestCreateTwiceReturnsDifferentIDs(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)

	a := createLink(t, mux, authHash)
	b := createLink(t, mux, authHash)
	if a.ID == b.ID {
		t.Errorf("two creations both got id %q, want distinct ids", a.ID)
	}
}

func TestCreateRejectsAnOwnerAuthHashOfTheWrongLength(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)

	rec := doJSON(t, mux, "/api/v1/request-links", createRequest{
		OwnerAuthHash: base64.StdEncoding.EncodeToString([]byte("too short")),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusBadRequest)
	}
}

func TestCreateRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)

	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/request-links", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusBadRequest)
	}
}

func submitPayload(t *testing.T, mux *http.ServeMux, id string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "/api/v1/request-links/"+id+"/submissions", submitRequest{
		Payload: base64.StdEncoding.EncodeToString(payload),
	})
}

func TestSubmitAcceptsAPayloadWithinTheLimit(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	rec := submitPayload(t, mux, link.ID, []byte("sealed bytes"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
}

func TestSubmitRefusesAnUnknownLink(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)

	rec := submitPayload(t, mux, "does-not-exist", []byte("x"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNotFound)
	}
}

func TestSubmitRefusesAPayloadLargerThanTheLimit(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	tooLarge := bytes.Repeat([]byte{0x41}, h.MaxSubmissionBytes+1)
	rec := submitPayload(t, mux, link.ID, tooLarge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusRequestEntityTooLarge)
	}
}

func TestSubmitRefusesOnceTheConcurrentSubmissionLimitIsReached(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.MaxConcurrentSubmissions = 1
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	first := submitPayload(t, mux, link.ID, []byte("one"))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, body = %s, want %d", first.Code, first.Body, http.StatusNoContent)
	}

	second := submitPayload(t, mux, link.ID, []byte("two"))
	if second.Code != http.StatusConflict {
		t.Fatalf("second submission status = %d, body = %s, want %d", second.Code, second.Body, http.StatusConflict)
	}
}

func TestSubmitAcceptsAPayloadAboveThePackageDefaultWhenConfigured(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	// Above DefaultMaxSubmissionBytes, which the JSON envelope limit must
	// not fall back to: it has to grow with this deployment's own
	// configured MaxSubmissionBytes instead of rejecting a payload the
	// operator explicitly allowed. 4 MiB configured with a 2 MiB payload is
	// the case that actually distinguishes the two envelopes: an envelope
	// still fixed at the package default only starts refusing a payload
	// above DefaultMaxSubmissionBytes+3064 bytes, so anything smaller would
	// pass against either envelope and prove nothing.
	h.MaxSubmissionBytes = 4 << 20
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	payload := bytes.Repeat([]byte{0x41}, 2<<20)
	rec := submitPayload(t, mux, link.ID, payload)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
}

func TestSubmitRefusesOnceTheLinkHasExpired(t *testing.T) {
	t.Parallel()

	h, now := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	*now = now.Add(h.Lifetime + time.Second)

	rec := submitPayload(t, mux, link.ID, []byte("too late"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNotFound)
	}
}

func TestSubmitIsRateLimitedPerLinkAndAddress(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.SubmitLimiter = ratelimit.New(1, time.Minute, 100)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	rec := submitFrom(t, mux, link.ID, "a", "203.0.113.5:1234")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}

	rec2 := submitFrom(t, mux, link.ID, "b", "203.0.113.5:5678")
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second submission from the same address status = %d, body = %s, want %d",
			rec2.Code, rec2.Body, http.StatusTooManyRequests)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header is empty on a 429")
	}

	rec3 := submitFrom(t, mux, link.ID, "c", "198.51.100.9:1234")
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("submission from a different address status = %d, body = %s, want %d",
			rec3.Code, rec3.Body, http.StatusNoContent)
	}
}

// submitFrom POSTs payload to id's submissions endpoint as if it arrived
// from remoteAddr, for the rate limit test: doJSON and submitPayload always
// resolve to the same test address, which this test needs to vary.
func submitFrom(t *testing.T, mux *http.ServeMux, id, payload, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(submitRequest{Payload: base64.StdEncoding.EncodeToString([]byte(payload))})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/request-links/"+id+"/submissions", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// proxyPeerAddr is the one reverse proxy TCP peer both
// TestNewHandlerTrustsNoProxyByDefault and
// TestNewHandlerResolvesClientAddressThroughATrustedProxy send every
// request through, matching h.ClientIP's trusted prefix in the latter.
const proxyPeerAddr = "203.0.113.5:1234"

// submitFromBehindProxy POSTs payload to id's submissions endpoint as if it
// arrived through proxyPeerAddr, the reverse proxy's own TCP connection,
// with forwardedFor as the client address that proxy appended to
// X-Forwarded-For. Whether that header is trusted at all is ClientIP's own
// decision, not something this helper can bypass.
func submitFromBehindProxy(t *testing.T, mux *http.ServeMux, id, payload, forwardedFor string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(submitRequest{Payload: base64.StdEncoding.EncodeToString([]byte(payload))})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/request-links/"+id+"/submissions", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", forwardedFor)
	req.RemoteAddr = proxyPeerAddr
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestNewHandlerTrustsNoProxyByDefault(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.SubmitLimiter = ratelimit.New(1, time.Minute, 100)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	// Both requests arrive through the same TCP peer, the shape every
	// submission takes behind a reverse proxy this handler was not told
	// to trust. With no trusted proxy configured, X-Forwarded-For is
	// never read, so both resolve to that one peer address and share its
	// rate limit bucket, the secure default NewHandler(nil) always gave.
	rec := submitFromBehindProxy(t, mux, link.ID, "a", "198.51.100.1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
	rec2 := submitFromBehindProxy(t, mux, link.ID, "b", "198.51.100.2")
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second submission through the untrusted peer, from a different forwarded address, status = %d, body = %s, want %d",
			rec2.Code, rec2.Body, http.StatusTooManyRequests)
	}
}

func TestNewHandlerResolvesClientAddressThroughATrustedProxy(t *testing.T) {
	t.Parallel()

	// Constructed through NewHandler itself, with a real trusted prefix,
	// the shape a deployment behind the chart's own Ingress configures:
	// the ingress pod's own address range, fed through
	// internal/config.TrustedProxies once this handler is wired into
	// cmd/burnlink. Assigning h.ClientIP afterwards instead would leave
	// trustedProxies on the path this test never exercises, since nothing
	// else in the repository constructs a Handler with a non-nil prefix.
	h := NewHandler(memstore.New(), []netip.Prefix{netip.MustParsePrefix("203.0.113.5/32")})
	h.SubmitLimiter = ratelimit.New(1, time.Minute, 100)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	// Both requests arrive through the same trusted proxy peer. Trusting
	// its X-Forwarded-For is what tells the two submitters apart instead
	// of collapsing them into the one rate limit bucket the previous test
	// shows an untrusted peer gets.
	rec := submitFromBehindProxy(t, mux, link.ID, "a", "198.51.100.1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
	rec2 := submitFromBehindProxy(t, mux, link.ID, "b", "198.51.100.2")
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second submission through the trusted proxy, from a different forwarded address, status = %d, body = %s, want %d",
			rec2.Code, rec2.Body, http.StatusNoContent)
	}
}

func TestOpenReturnsAndRemovesEverySubmissionWaiting(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	authValue, authHash := ownerAuth(7)
	link := createLink(t, mux, authHash)

	first := submitPayload(t, mux, link.ID, []byte("one"))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, want %d", first.Code, http.StatusNoContent)
	}
	second := submitPayload(t, mux, link.ID, []byte("two"))
	if second.Code != http.StatusNoContent {
		t.Fatalf("second submission status = %d, want %d", second.Code, http.StatusNoContent)
	}

	rec := doJSON(t, mux, "/api/v1/request-links/"+link.ID+"/open", openRequest{
		OwnerAuth: base64.StdEncoding.EncodeToString(authValue),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("open status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusOK)
	}
	var resp openResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode open response: %v", err)
	}
	got := map[string]bool{}
	for _, encoded := range resp.Submissions {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode submission: %v", err)
		}
		got[string(decoded)] = true
	}
	if !got["one"] || !got["two"] || len(got) != 2 {
		t.Fatalf("submissions = %v, want exactly {one, two}", got)
	}

	again := doJSON(t, mux, "/api/v1/request-links/"+link.ID+"/open", openRequest{
		OwnerAuth: base64.StdEncoding.EncodeToString(authValue),
	})
	if again.Code != http.StatusOK {
		t.Fatalf("second open status = %d, body = %s, want %d", again.Code, again.Body, http.StatusOK)
	}
	var secondResp openResponse
	if err := json.Unmarshal(again.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("decode second open response: %v", err)
	}
	if len(secondResp.Submissions) != 0 {
		t.Errorf("second open returned %v, want an empty list: submissions are consumed once", secondResp.Submissions)
	}
}

func TestOpenRefusesTheWrongOwnerAuth(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	wrongValue, _ := ownerAuth(2)
	rec := doJSON(t, mux, "/api/v1/request-links/"+link.ID+"/open", openRequest{
		OwnerAuth: base64.StdEncoding.EncodeToString(wrongValue),
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d (indistinguishable from an unknown link)", rec.Code, rec.Body, http.StatusNotFound)
	}
}

func TestOpenRefusesAnUnknownLink(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	authValue, _ := ownerAuth(1)

	rec := doJSON(t, mux, "/api/v1/request-links/does-not-exist/open", openRequest{
		OwnerAuth: base64.StdEncoding.EncodeToString(authValue),
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNotFound)
	}
}

func openAs(t *testing.T, mux *http.ServeMux, id string, authValue []byte) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, "/api/v1/request-links/"+id+"/open", openRequest{
		OwnerAuth: base64.StdEncoding.EncodeToString(authValue),
	})
}

func TestOpenFreesSlotsForLaterSubmissions(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.MaxConcurrentSubmissions = 1
	mux := newMux(h)
	authValue, authHash := ownerAuth(3)
	link := createLink(t, mux, authHash)

	if rec := submitPayload(t, mux, link.ID, []byte("one")); rec.Code != http.StatusNoContent {
		t.Fatalf("first submission status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec := submitPayload(t, mux, link.ID, []byte("two")); rec.Code != http.StatusConflict {
		t.Fatalf("submission to a full link status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if rec := openAs(t, mux, link.ID, authValue); rec.Code != http.StatusOK {
		t.Fatalf("open status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusOK)
	}
	// The slot the open call freed is reused: the cap is on submissions
	// waiting at once, not a lifetime total.
	if rec := submitPayload(t, mux, link.ID, []byte("three")); rec.Code != http.StatusNoContent {
		t.Fatalf("submission after open status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
	rec := openAs(t, mux, link.ID, authValue)
	var resp openResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode open response: %v", err)
	}
	if len(resp.Submissions) != 1 {
		t.Fatalf("second open returned %d submissions, want 1", len(resp.Submissions))
	}
	if got, _ := base64.StdEncoding.DecodeString(resp.Submissions[0]); string(got) != "three" {
		t.Errorf("second open returned %q, want %q", got, "three")
	}
}

func TestOpenRefusesAnExpiredLink(t *testing.T) {
	t.Parallel()

	h, now := newTestHandler(t)
	mux := newMux(h)
	authValue, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)
	if rec := submitPayload(t, mux, link.ID, []byte("x")); rec.Code != http.StatusNoContent {
		t.Fatalf("submission status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	*now = now.Add(h.Lifetime + time.Second)

	rec := openAs(t, mux, link.ID, authValue)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNotFound)
	}
}

func TestSubmitAcceptsAPayloadOfExactlyTheLimit(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	exact := bytes.Repeat([]byte{0x41}, h.MaxSubmissionBytes)
	rec := submitPayload(t, mux, link.ID, exact)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusNoContent)
	}
}

func TestCreateIsRateLimitedPerAddress(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.CreateLimiter = ratelimit.New(1, time.Minute, 100)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	body, err := json.Marshal(createRequest{OwnerAuthHash: base64.StdEncoding.EncodeToString(authHash)})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	create := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/request-links", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := create("203.0.113.5:1"); rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if rec := create("203.0.113.5:2"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second create from the same address status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec := create("198.51.100.9:1"); rec.Code != http.StatusCreated {
		t.Fatalf("create from a different address status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestOpenIsRateLimitedPerLinkAndAddress(t *testing.T) {
	t.Parallel()

	h, _ := newTestHandler(t)
	h.LookupLimiter = ratelimit.New(1, time.Minute, 100)
	mux := newMux(h)
	authValue, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)
	body, err := json.Marshal(openRequest{OwnerAuth: base64.StdEncoding.EncodeToString(authValue)})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	open := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/request-links/"+link.ID+"/open", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := open("203.0.113.5:1"); rec.Code != http.StatusOK {
		t.Fatalf("first open status = %d, want %d", rec.Code, http.StatusOK)
	}
	rec := open("203.0.113.5:2")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second open from the same address status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header is empty on a 429")
	}
	if rec := open("198.51.100.9:1"); rec.Code != http.StatusOK {
		t.Fatalf("open from a different address status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func getInfo(t *testing.T, mux *http.ServeMux, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/request-links/"+id, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestInfoReturnsTheLimitsOfALink(t *testing.T) {
	t.Parallel()

	h, now := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	rec := getInfo(t, mux, link.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body, http.StatusOK)
	}
	var resp infoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode info response: %v", err)
	}
	if resp.MaxSubmissionBytes != h.MaxSubmissionBytes {
		t.Errorf("MaxSubmissionBytes = %d, want %d", resp.MaxSubmissionBytes, h.MaxSubmissionBytes)
	}
	if !resp.ExpiresAt.Equal(now.Add(h.Lifetime)) {
		t.Errorf("ExpiresAt = %v, want %v", resp.ExpiresAt, now.Add(h.Lifetime))
	}
}

func TestInfoRefusesAnUnknownOrExpiredLink(t *testing.T) {
	t.Parallel()

	h, now := newTestHandler(t)
	mux := newMux(h)
	_, authHash := ownerAuth(1)
	link := createLink(t, mux, authHash)

	if rec := getInfo(t, mux, "does-not-exist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown link status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	*now = now.Add(h.Lifetime + time.Second)
	if rec := getInfo(t, mux, link.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("expired link status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

var _ store.Store = memstore.New() // Handler is written against the interface, not the concrete store.
