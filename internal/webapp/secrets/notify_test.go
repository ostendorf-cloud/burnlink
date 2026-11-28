// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostendorf-cloud/govue/middleware"

	"github.com/ostendorf-cloud/burnlink/internal/notify"
)

const hook = "https://hooks.example.com/burnlink?token=t0ken"

// fakeNotifier validates like the real one and records what it was asked to
// deliver instead of delivering it.
type fakeNotifier struct {
	mu   sync.Mutex
	sent []delivery
}

type delivery struct {
	id         string
	redeemedAt time.Time
	target     string
}

func (*fakeNotifier) Validate(raw string) error { return notify.Validate(raw) }

func (f *fakeNotifier) Notify(_ context.Context, id string, at time.Time, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, delivery{id: id, redeemedAt: at, target: target})
}

func (f *fakeNotifier) deliveries() []delivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]delivery(nil), f.sent...)
}

func withNotifier(n Notifier) func(*Config) { return func(c *Config) { c.Notifier = n } }

func notifyBody(url string) string {
	return `{"ciphertext":"` + b64 + `","notifyUrl":` + jsonString(url) + `}`
}

func jsonString(s string) string {
	out, _ := json.Marshal(s)
	return string(out)
}

func TestStoreRefusesAnInvalidNotifyURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
	}{
		{name: "http", url: "http://hooks.example.com/x"},
		{name: "loopback", url: "https://127.0.0.1/x"},
		{name: "metadata address", url: "https://169.254.169.254/latest"},
		{name: "private", url: "https://10.0.0.1/x"},
		{name: "user info", url: "https://user:pw@hooks.example.com/x"},
		{name: "port", url: "https://hooks.example.com:8443/x"},
		{name: "not a url", url: "not a url"},
		{name: "too long", url: "https://hooks.example.com/" + strings.Repeat("a", notify.MaxTargetBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			n := &fakeNotifier{}
			hn := newHarness(t, withNotifier(n))
			rec := hn.do(http.MethodPost, "/api/v1/secrets", notifyBody(tc.url))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body %s", rec.Code, rec.Body)
			}
			if got := errorCode(t, rec); got != "invalid_argument" {
				t.Errorf("error code = %q, want invalid_argument", got)
			}
			// The message is fixed: it repeats nothing the sender wrote.
			for _, part := range []string{"hooks.example.com", "127.0.0.1", "169.254", "user:pw", "not a url"} {
				if strings.Contains(rec.Body.String(), part) {
					t.Errorf("body %s repeats %q", rec.Body, part)
				}
			}
			if hn.puts.Load() != 0 {
				t.Errorf("a refused request stored %d keys, want 0", hn.puts.Load())
			}
		})
	}
}

func TestStoreRefusesANotifyURLWithoutANotifier(t *testing.T) {
	t.Parallel()

	hn := newHarness(t)
	rec := hn.do(http.MethodPost, "/api/v1/secrets", notifyBody(hook))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body %s", rec.Code, rec.Body)
	}
	if hn.puts.Load() != 0 {
		t.Errorf("a refused request stored %d keys, want 0", hn.puts.Load())
	}
}

func TestOpenNotifiesOnceAndDeletesTheTarget(t *testing.T) {
	t.Parallel()

	n := &fakeNotifier{}
	hn := newHarness(t, withNotifier(n))
	id := hn.put(notifyBody(hook))
	if got := len(n.deliveries()); got != 0 {
		t.Fatalf("%d notifications before the secret was opened, want 0", got)
	}

	// Checking is not redeeming.
	hn.do(http.MethodHead, "/api/v1/secrets/"+id, "")
	if got := len(n.deliveries()); got != 0 {
		t.Fatalf("%d notifications after a check, want 0", got)
	}

	rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d, body %s", rec.Code, rec.Body)
	}
	got := n.deliveries()
	if len(got) != 1 {
		t.Fatalf("%d notifications, want 1", len(got))
	}
	if got[0].id != id || got[0].target != hook || !got[0].redeemedAt.Equal(*hn.now) {
		t.Errorf("delivery = %+v, want the id, the target and the time of the open", got[0])
	}

	// The target left the store with the secret.
	target, err := hn.vault.TakeTarget(t.Context(), id)
	if err != nil || target != "" {
		t.Errorf("TakeTarget() after open = %q, %v, want it gone", target, err)
	}
	// A second open is the refusal and notifies nobody.
	if rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}"); rec.Code != http.StatusNotFound {
		t.Errorf("second open = %d, want 404", rec.Code)
	}
	if got := len(n.deliveries()); got != 1 {
		t.Errorf("%d notifications after a second open, want still 1", got)
	}
}

func TestOpenWithoutATargetNotifiesNobody(t *testing.T) {
	t.Parallel()

	n := &fakeNotifier{}
	hn := newHarness(t, withNotifier(n))
	id := hn.put(`{"ciphertext":"` + b64 + `"}`)
	rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d, body %s", rec.Code, rec.Body)
	}
	if got := len(n.deliveries()); got != 0 {
		t.Errorf("%d notifications, want 0", got)
	}
}

func TestRefusedOpenNotifiesNobody(t *testing.T) {
	t.Parallel()

	n := &fakeNotifier{}
	hn := newHarness(t, withNotifier(n))
	hn.do(http.MethodPost, "/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAQ/open", "{}")
	hn.do(http.MethodPost, "/api/v1/secrets/not-an-id/open", "{}")
	if got := len(n.deliveries()); got != 0 {
		t.Errorf("%d notifications, want 0", got)
	}
}

func TestTargetExpiresWithTheSecret(t *testing.T) {
	t.Parallel()

	hn := newHarness(t, withNotifier(&fakeNotifier{}))
	id := hn.put(`{"ciphertext":"` + b64 + `","lifetimeSeconds":60,"notifyUrl":` + jsonString(hook) + `}`)
	*hn.now = hn.now.Add(61 * time.Second)

	target, err := hn.vault.TakeTarget(t.Context(), id)
	if err != nil || target != "" {
		t.Errorf("TakeTarget() after the lifetime = %q, %v, want it gone", target, err)
	}
}

// targetFailVault stores and takes secrets through the real vault but fails
// every target read, standing for a store that drops out between two calls.
type targetFailVault struct{ Vault }

func (targetFailVault) TakeTarget(context.Context, string) (string, error) {
	return "", errors.New("dial tcp: boom")
}

// A failed notification never blocks or reverses the redemption.
func TestOpenSurvivesATargetReadFailure(t *testing.T) {
	t.Parallel()

	var buf lockedBuffer
	logger := newTestLogger(&buf)
	n := &fakeNotifier{}
	hn := newHarness(t, withNotifier(n), func(c *Config) { c.Vault = targetFailVault{c.Vault} })
	chain := middleware.Chain(hn.handler, middleware.RequestID(logger))

	id := hn.put(notifyBody(hook))
	rec := serve(t, chain, http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d, want 200, body %s", rec.Code, rec.Body)
	}
	var out openResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Ciphertext != b64 {
		t.Errorf("open body = %s, want the ciphertext", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("the cause reached the client: %s", rec.Body)
	}
	if got := len(n.deliveries()); got != 0 {
		t.Errorf("%d notifications, want 0 when the target could not be read", got)
	}
	if !strings.Contains(buf.String(), "pickup notification target not read") {
		t.Errorf("the failure was not logged:\n%s", buf.String())
	}
}

// A delivery that fails is the notifier's to log: Notify cannot fail, so the
// redemption answers the same with a notifier whose every delivery is dropped.
func TestOpenWhenTheDeliveryIsDropped(t *testing.T) {
	t.Parallel()

	var buf lockedBuffer
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })
	n := notify.New(notify.Config{
		Logger:    newTestLogger(&buf),
		Transport: rt,
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	hn := newHarness(t, withNotifier(n))
	id := hn.put(notifyBody(hook))
	rec := hn.do(http.MethodPost, "/api/v1/secrets/"+id+"/open", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d, want 200, body %s", rec.Code, rec.Body)
	}
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !strings.Contains(buf.String(), "pickup notification given up") {
		t.Errorf("the dropped delivery was not logged:\n%s", buf.String())
	}
	for _, leak := range []string{"hooks.example.com", "t0ken", id} {
		if strings.Contains(buf.String(), leak) {
			t.Errorf("the log contains %q:\n%s", leak, buf.String())
		}
	}
}

// putFailVault fails the secret write but takes targets.
type putFailVault struct {
	Vault
	mu      sync.Mutex
	targets map[string]string
}

func (v *putFailVault) PutTarget(_ context.Context, id, target string, _ time.Duration) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.targets[id] = target
	return nil
}

func (v *putFailVault) TakeTarget(_ context.Context, id string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.targets[id]
	delete(v.targets, id)
	return t, nil
}

func (*putFailVault) Put(context.Context, string, []byte, time.Duration) error {
	return errors.New("dial tcp: boom")
}

func TestFailedStoreLeavesNoTargetBehind(t *testing.T) {
	t.Parallel()

	v := &putFailVault{targets: map[string]string{}}
	hn := newHarness(t, withNotifier(&fakeNotifier{}), func(c *Config) { v.Vault = c.Vault; c.Vault = v })
	rec := hn.do(http.MethodPost, "/api/v1/secrets", notifyBody(hook))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.targets) != 0 {
		t.Errorf("%d targets left after a failed store, want 0", len(v.targets))
	}
}

// TestNotificationBodyCarriesNoPayload runs the whole path with the real
// notifier and a recording transport: store a secret with a target, open it,
// and look at the request that would have gone out.
func TestNotificationBodyCarriesNoPayload(t *testing.T) {
	t.Parallel()

	const plain = "tops3cret-payload-0123456789"
	ciphertext := base64.StdEncoding.EncodeToString([]byte(plain))

	sent := make(chan []byte, 1)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		sent <- body
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})
	n := notify.New(notify.Config{Transport: rt, Sleep: func(context.Context, time.Duration) error { return nil }})

	hn := newHarness(t, withNotifier(n), func(c *Config) { c.MaxBytes = 64 })
	rec := hn.do(http.MethodPost, "/api/v1/secrets", `{"ciphertext":"`+ciphertext+`","notifyUrl":`+jsonString(hook)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("store = %d, body %s", rec.Code, rec.Body)
	}
	var stored storeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if rec := hn.do(http.MethodPost, "/api/v1/secrets/"+stored.ID+"/open", "{}"); rec.Code != http.StatusOK {
		t.Fatalf("open = %d, body %s", rec.Code, rec.Body)
	}
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var body []byte
	select {
	case body = <-sent:
	default:
		t.Fatal("no notification was sent")
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("body %q is not JSON: %v", body, err)
	}
	if len(fields) != 2 || fields["id"] != stored.ID || fields["redeemedAt"] != "2026-01-01T00:00:00Z" {
		t.Errorf("body = %s, want exactly the id and the time", body)
	}
	for _, leak := range []string{plain, ciphertext, "ciphertext", "payload", hook, "t0ken"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("body %s contains %q", body, leak)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTargetIsNeverAnswered(t *testing.T) {
	t.Parallel()

	hn := newHarness(t, withNotifier(&fakeNotifier{}))
	rec := hn.do(http.MethodPost, "/api/v1/secrets", notifyBody(hook))
	if rec.Code != http.StatusCreated {
		t.Fatalf("store = %d, body %s", rec.Code, rec.Body)
	}
	var out storeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	opened := hn.do(http.MethodPost, "/api/v1/secrets/"+out.ID+"/open", "{}")
	for _, body := range []string{rec.Body.String(), opened.Body.String()} {
		for _, leak := range []string{"hooks.example.com", "t0ken"} {
			if strings.Contains(body, leak) {
				t.Errorf("answer %s contains %q", body, leak)
			}
		}
	}
}
