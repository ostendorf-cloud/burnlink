// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/memstore"
	"github.com/ostendorf-cloud/burnlink/internal/webapp/secrets"
)

type memBackend struct{ *memstore.Store }

func (memBackend) Ping(context.Context) error { return nil }

// The fake server of the other tests is what this package believes about the
// API. This test mounts the real handler, with its content type guard, its
// CSRF check, its limits and its error shape, so the belief is checked.
func TestSendAndOpen_againstTheRealHandler(t *testing.T) {
	t.Parallel()
	h, err := secrets.New(secrets.Config{
		Vault:           store.NewSecrets(memBackend{memstore.New()}),
		MaxBytes:        4096,
		LifetimeMin:     time.Minute,
		LifetimeMax:     time.Hour,
		LifetimeDefault: 10 * time.Minute,
		Limiter:         ratelimit.New(10_000, time.Minute, 100),
		ClientIP:        clientip.NewResolver(nil),
	})
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(secrets.NoStoreOnAPI(mux))
	t.Cleanup(srv.Close)

	env := func(stdin string) options { return options{stdin: stdin} }
	text := "from the terminal ✓\nsecond line"
	sent := runAgainst(t, srv, env(text), "send", "--server", srv.URL, "--lifetime", "5m")
	l := link(t, sent)

	opened := runAgainst(t, srv, options{}, "open", l)
	if opened.code != 0 || opened.stdout != text {
		t.Fatalf("open = %d %q %q", opened.code, opened.stdout, opened.stderr)
	}
	again := runAgainst(t, srv, options{}, "open", l)
	if again.code != 1 || !strings.Contains(again.stderr, "not available") {
		t.Errorf("second open = %d %q, want the one refusal", again.code, again.stderr)
	}

	tooLong := runAgainst(t, srv, env("x"), "send", "--server", srv.URL, "--lifetime", "2h")
	if tooLong.code != 1 || !strings.Contains(tooLong.stderr, "between 1m0s and 1h0m0s") {
		t.Errorf("lifetime above the server's maximum = %d %q", tooLong.code, tooLong.stderr)
	}
}

func runAgainst(t *testing.T, srv *httptest.Server, opts options, args ...string) result {
	t.Helper()
	return run(t, &fakeServer{srv: srv}, opts, args...)
}
