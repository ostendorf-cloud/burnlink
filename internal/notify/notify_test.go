// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const target = "https://hooks.example.com/burnlink?token=t0ken"

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}

// sent is one request the fake transport received.
type sent struct {
	method string
	url    string
	header http.Header
	body   []byte
}

// fakeTransport answers each request with the next canned answer, the last
// one for every further request, and records what it was sent. No network.
type fakeTransport struct {
	mu      sync.Mutex
	answers []func(*http.Request) (*http.Response, error)
	got     []sent
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, sent{method: r.Method, url: r.URL.String(), header: r.Header.Clone(), body: body})
	i := min(len(f.got)-1, len(f.answers)-1)
	answer := f.answers[i]
	f.mu.Unlock()
	return answer(r)
}

func (f *fakeTransport) requests() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.got...)
}

func status(code int) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}
}

func redirect(location string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{"Location": {location}},
			Request:    r,
		}, nil
	}
}

func failing(r *http.Request) (*http.Response, error) {
	return nil, errors.New("connection reset by " + r.URL.Host)
}

// waits records the waits between attempts instead of sleeping them.
type waits struct {
	mu sync.Mutex
	d  []time.Duration
}

func (w *waits) sleep(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.d = append(w.d, d)
	return nil
}

func (w *waits) list() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.d...)
}

// run notifies once and waits for the delivery to end.
func run(t *testing.T, ft *fakeTransport, w *waits, logs io.Writer, to string) {
	t.Helper()
	n := New(Config{Logger: newTestLogger(logs), Transport: ft, Sleep: w.sleep})
	n.Notify(t.Context(), "id22", time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)), to)
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDeliveryAndRetry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		answers   []func(*http.Request) (*http.Response, error)
		to        string
		wantReqs  int
		wantWaits []time.Duration
		wantLog   string
	}{
		{name: "first attempt succeeds", answers: []func(*http.Request) (*http.Response, error){status(204)}, to: target, wantReqs: 1},
		{name: "any 2xx succeeds", answers: []func(*http.Request) (*http.Response, error){status(202)}, to: target, wantReqs: 1},
		{
			name: "server error then success", answers: []func(*http.Request) (*http.Response, error){status(500), status(200)},
			to: target, wantReqs: 2, wantWaits: []time.Duration{time.Second},
		},
		{
			name: "transport error then success", answers: []func(*http.Request) (*http.Response, error){failing, status(200)},
			to: target, wantReqs: 2, wantWaits: []time.Duration{time.Second},
		},
		{
			name: "too many requests is retried", answers: []func(*http.Request) (*http.Response, error){status(429), status(200)},
			to: target, wantReqs: 2, wantWaits: []time.Duration{time.Second},
		},
		{
			name: "request timeout is retried", answers: []func(*http.Request) (*http.Response, error){status(408), status(200)},
			to: target, wantReqs: 2, wantWaits: []time.Duration{time.Second},
		},
		{
			name: "gives up after three attempts", answers: []func(*http.Request) (*http.Response, error){status(503)},
			to: target, wantReqs: 3, wantWaits: []time.Duration{time.Second, 4 * time.Second}, wantLog: "unexpected status",
		},
		{
			name: "gives up after three transport errors", answers: []func(*http.Request) (*http.Response, error){failing},
			to: target, wantReqs: 3, wantWaits: []time.Duration{time.Second, 4 * time.Second}, wantLog: "request failed",
		},
		{name: "client error is not retried", answers: []func(*http.Request) (*http.Response, error){status(400)}, to: target, wantReqs: 1, wantLog: "unexpected status"},
		{name: "not found is not retried", answers: []func(*http.Request) (*http.Response, error){status(404)}, to: target, wantReqs: 1, wantLog: "unexpected status"},
		{name: "a redirect is refused, not followed", answers: []func(*http.Request) (*http.Response, error){redirect("https://169.254.169.254/latest"), status(200)}, to: target, wantReqs: 1, wantLog: "unexpected status"},
		{name: "http is refused before any request", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "http://hooks.example.com/x", wantReqs: 0, wantLog: "invalid url"},
		// A stored target that fails Validate is not delivered, whatever put it in the
		// store: every store time check stays in force at delivery.
		{name: "another port is refused before any request", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "https://hooks.example.com:8443/x", wantReqs: 0, wantLog: "invalid url"},
		{name: "user information is refused before any request", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "https://user:pw@hooks.example.com/x", wantReqs: 0, wantLog: "invalid url"},
		{name: "a fragment is refused before any request", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "https://hooks.example.com/x#f", wantReqs: 0, wantLog: "invalid url"},
		{name: "a blocked address literal is refused before any request", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "https://10.0.0.1/x", wantReqs: 0, wantLog: "invalid url"},
		{name: "unparsable url is refused", answers: []func(*http.Request) (*http.Response, error){status(200)}, to: "https://[::1", wantReqs: 0, wantLog: "invalid url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ft := &fakeTransport{answers: tc.answers}
			w := &waits{}
			var logs strings.Builder
			run(t, ft, w, &logs, tc.to)

			if got := len(ft.requests()); got != tc.wantReqs {
				t.Errorf("requests = %d, want %d", got, tc.wantReqs)
			}
			gotWaits := w.list()
			if len(gotWaits) != len(tc.wantWaits) {
				t.Fatalf("waits = %v, want %v", gotWaits, tc.wantWaits)
			}
			for i := range gotWaits {
				if gotWaits[i] != tc.wantWaits[i] {
					t.Errorf("wait %d = %v, want %v", i, gotWaits[i], tc.wantWaits[i])
				}
			}
			if tc.wantLog == "" && logs.Len() != 0 {
				t.Errorf("log = %q, want none", logs.String())
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Errorf("log = %q, want it to contain %q", logs.String(), tc.wantLog)
			}
			// Whatever went wrong, the log never names the destination.
			for _, leak := range []string{"hooks.example.com", "t0ken", "169.254.169.254", "id22"} {
				if strings.Contains(logs.String(), leak) {
					t.Errorf("log %q contains %q", logs.String(), leak)
				}
			}
		})
	}
}

func TestRequestShape(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){status(200)}}
	run(t, ft, &waits{}, io.Discard, target)

	reqs := ft.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	got := reqs[0]
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.url != target {
		t.Errorf("url = %s, want the stored one", got.url)
	}
	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	for _, h := range []string{"Authorization", "Cookie"} {
		if v := got.header.Get(h); v != "" {
			t.Errorf("header %s = %q, want none", h, v)
		}
	}

	var fields map[string]any
	if err := json.Unmarshal(got.body, &fields); err != nil {
		t.Fatalf("body %q is not JSON: %v", got.body, err)
	}
	if len(fields) != 2 || fields["id"] != "id22" || fields["redeemedAt"] != "2026-01-02T02:04:05Z" {
		t.Errorf("body = %s, want exactly the id and the time in UTC", got.body)
	}
	if len(got.body) > 256 {
		t.Errorf("body is %d bytes, want it small by construction", len(got.body))
	}
}

func TestNotifyAfterCloseDoesNothing(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){status(200)}}
	n := New(Config{Transport: ft, Sleep: (&waits{}).sleep})
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	n.Notify(t.Context(), "id22", time.Now(), target)
	if got := len(ft.requests()); got != 0 {
		t.Errorf("requests after Close = %d, want 0", got)
	}
}

// A notification outlives the request that caused it: the redemption's own
// context ends as soon as its answer is written.
func TestDeliveryIgnoresTheCallersCancellation(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){status(200)}}
	n := New(Config{Transport: ft, Sleep: (&waits{}).sleep})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	n.Notify(ctx, "id22", time.Now(), target)
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := len(ft.requests()); got != 1 {
		t.Errorf("requests = %d, want 1", got)
	}
}

func TestNotifyDoesNotBlockOnASlowDestination(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	slow := func(r *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-release
		return status(200)(r)
	}
	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){slow}}
	n := New(Config{Transport: ft, Sleep: (&waits{}).sleep})

	returned := make(chan struct{})
	go func() {
		n.Notify(t.Context(), "id22", time.Now(), target)
		close(returned)
	}()
	<-returned // Notify came back while the destination is still holding the request.
	<-started
	close(release)
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestInFlightLimit(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(maxInFlight)
	var once sync.Map
	hold := func(r *http.Request) (*http.Response, error) {
		if _, loaded := once.LoadOrStore(r.URL.Query().Get("n"), true); !loaded {
			started.Done()
		}
		<-release
		return status(200)(r)
	}
	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){hold}}
	var logs strings.Builder
	n := New(Config{Logger: newTestLogger(&logs), Transport: ft, Sleep: (&waits{}).sleep})

	for i := range maxInFlight {
		n.Notify(t.Context(), "id22", time.Now(), target+"&n="+string(rune('A'+i)))
	}
	started.Wait()
	// The limit is reached: one more is dropped and said so.
	n.Notify(t.Context(), "id22", time.Now(), target+"&n=extra")
	close(release)
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := len(ft.requests()); got != maxInFlight {
		t.Errorf("requests = %d, want %d", got, maxInFlight)
	}
	if !strings.Contains(logs.String(), "too many in flight") {
		t.Errorf("log = %q, want the drop to be logged", logs.String())
	}
}

func TestCloseGivesUpWhenItsContextEnds(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{})
	hold := func(r *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return status(200)(r)
	}
	ft := &fakeTransport{answers: []func(*http.Request) (*http.Response, error){hold}}
	n := New(Config{Transport: ft, Sleep: (&waits{}).sleep})
	n.Notify(t.Context(), "id22", time.Now(), target)
	<-started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := n.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close() = %v, want context.Canceled", err)
	}
}
