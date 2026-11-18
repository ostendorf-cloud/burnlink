// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Command burnlink serves the embedded Vue build and the one time secret
// API (internal/webapp/secrets), and answers health/readiness/metrics on
// govue's admin listener. Readiness includes the Redis-compatible store,
// configured through internal/config.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/health"
	"github.com/ostendorf-cloud/govue/httpserver"
	"github.com/ostendorf-cloud/govue/logging"
	"github.com/ostendorf-cloud/govue/metrics"
	"github.com/ostendorf-cloud/govue/middleware"
	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/config"
	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/redisstore"
	"github.com/ostendorf-cloud/burnlink/internal/webapp/secrets"
)

// rateLimitKeys bounds how many client addresses the limiter tracks at once.
const rateLimitKeys = 100_000

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, cfg.LogLevel)

	client, err := redisstore.New(redisstore.Options{
		Addr:     cfg.Store.Addr,
		Username: cfg.Store.Username,
		Password: cfg.Store.Password,
		TLS:      cfg.Store.TLS,
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	// The store is part of readiness, so a pod that cannot reach it never
	// receives traffic, and it backs the secret endpoints.
	secrets := store.NewSecrets(client)

	publicHandler, err := buildHandler(logger, cfg, secrets)
	if err != nil {
		return err
	}

	healthRegistry := health.New()
	addStoreCheck(healthRegistry, secrets)
	adminHandler := buildAdminHandler(logger, healthRegistry)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return httpserver.RunAdmin(ctx, httpserver.Config{
		Addr:    cfg.Addr,
		Handler: publicHandler,
		Logger:  logger,
		// Failing the readiness probe before the drain delay starts is
		// what lets a load balancer stop sending new requests before the
		// server stops accepting connections at all.
		BeforeShutdown: healthRegistry.Drain,
	}, httpserver.AdminConfig{
		Addr:    cfg.AdminAddr,
		Handler: adminHandler,
	})
}

// pinger is what readiness needs from the store.
type pinger interface {
	Ping(ctx context.Context) error
}

// addStoreCheck makes readiness unready while the store does not answer.
// Liveness stays untouched: restarting this process would not bring the
// store back. govue's registry reports the failed check by name only and
// logs the cause.
func addStoreCheck(registry *health.Registry, p pinger) {
	registry.Add("store", 0, p.Ping)
}

// buildHandler serves the embedded SPA bundle and the secret API behind
// govue's default security headers and access log. The client address, for
// the rate limit and the access log alike, is resolved from the trusted
// proxy ranges in cfg.
func buildHandler(logger *slog.Logger, cfg config.Config, vault secrets.Vault) (http.Handler, error) {
	dist, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, fmt.Errorf("burnlink: %w", err)
	}

	clientIPs := clientip.NewResolver(cfg.TrustedProxies)
	api, err := secrets.New(secrets.Config{
		Vault:           vault,
		MaxBytes:        cfg.Secrets.MaxBytes,
		LifetimeMin:     cfg.Secrets.LifetimeMin,
		LifetimeMax:     cfg.Secrets.LifetimeMax,
		LifetimeDefault: cfg.Secrets.LifetimeDefault,
		Limiter:         ratelimit.New(cfg.RateLimit.Burst, cfg.RateLimit.Per, rateLimitKeys),
		ClientIP:        clientIPs,
	})
	if err != nil {
		return nil, fmt.Errorf("burnlink: %w", err)
	}

	mux := http.NewServeMux()
	api.Register(mux)
	files := http.FileServerFS(dist)
	mux.Handle("/", files)
	// The SPA tells its pages apart by their path alone, so the server
	// answers exactly the paths App.vue knows with index.html instead of a
	// 404: /security and /r/<id>. Everything else, /api/ included, stays
	// with the file server and answers 404 when no such file exists. A GET
	// pattern also matches HEAD. {id} spans one non-empty path segment, the
	// same shape App.vue's own /r/<id> match accepts, so /r/ and /r/a/b stay
	// 404. Everything under /api/ is answered by api.Register above, JSON
	// 404 included, so the file server never sees an API path.
	index := func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		r2.URL.RawPath = ""
		files.ServeHTTP(w, r2)
	}
	mux.HandleFunc("GET /security", index)
	mux.HandleFunc("GET /r/{id}", index)

	accessLog := middleware.AccessLog{ClientIP: clientIPs}
	security := middleware.DefaultSecurity()

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.RequestID(logger),
		security.Middleware,
		accessLog.Middleware,
	), nil
}

// buildAdminHandler builds the handler httpserver.RunAdmin serves on the
// second, administrative listener: liveness, readiness and the Prometheus
// scrape, none of which this application's Ingress ever routes to. The
// middleware here is a deliberate, short list, not the public chain above
// with entries removed: a probe and a scrape are not browser traffic, so
// the security headers and the access log have nothing to protect or
// record. Recover and RequestID stay, because a panic here is still worth
// catching and still worth a correlatable log line. See govue's
// example/app.go for the same reasoning in full.
func buildAdminHandler(logger *slog.Logger, healthRegistry *health.Registry) http.Handler {
	mux := http.NewServeMux()
	healthRegistry.Handle(mux)

	registry := metrics.NewRegistry()
	mux.Handle("GET /metrics", metrics.Handler(registry))

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.RequestID(logger),
	)
}
