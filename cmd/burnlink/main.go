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
	"strings"
	"syscall"
	"time"

	"github.com/ostendorf-cloud/govue/analytics"
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

	// Page views are counted from the server, off unless both UMAMI_URL and
	// UMAMI_WEBSITE_ID are set. The queued views are sent on shutdown within
	// a bounded time.
	views, err := newViews(logger, cfg, nil)
	if err != nil {
		return err
	}
	defer closeViews(logger, views)

	publicHandler, err := buildPublicHandler(logger, cfg, secrets, views)
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

// viewsCloseTimeout bounds how long shutdown waits for queued page views.
const viewsCloseTimeout = 5 * time.Second

// newViews builds the page view counter. httpClient is nil in production,
// which gives govue's default client (no proxy, no cookies, no redirects).
// Without UMAMI_URL and UMAMI_WEBSITE_ID the client is inert.
func newViews(logger *slog.Logger, cfg config.Config, httpClient *http.Client) (*analytics.Client, error) {
	views, err := analytics.New(cfg.Umami, analytics.Options{
		Hostname:   cfg.SiteURL.Hostname(),
		Logger:     logger,
		HTTPClient: httpClient,
		ClientIP:   clientip.NewResolver(cfg.TrustedProxies),
		// Only pages are counted. The API answers JSON, which govue leaves
		// out already, and this keeps an API route out whatever it answers.
		Skip: func(r *http.Request) bool {
			return r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
		},
	})
	if err != nil {
		return nil, fmt.Errorf("burnlink: %w", err)
	}
	if views.Enabled() {
		logger.Info("page view counting is on")
	} else {
		logger.Info("page view counting is off")
	}
	return views, nil
}

// closeViews sends the queued views within viewsCloseTimeout.
func closeViews(logger *slog.Logger, views *analytics.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), viewsCloseTimeout)
	defer cancel()
	if err := views.Close(ctx); err != nil {
		logger.Warn("page views were lost on shutdown", "error", err)
	}
}

// buildHandler is buildPublicHandler with page view counting off.
func buildHandler(logger *slog.Logger, cfg config.Config, vault secrets.Vault) (http.Handler, error) {
	off, err := analytics.New(analytics.Config{}, analytics.Options{})
	if err != nil {
		return nil, fmt.Errorf("burnlink: %w", err)
	}
	return buildPublicHandler(logger, cfg, vault, off)
}

// buildPublicHandler serves the embedded SPA bundle and the secret API behind
// govue's default security headers and access log. The client address, for
// the rate limit and the access log alike, is resolved from the trusted
// proxy ranges in cfg. views counts a page view after the page was served.
// It wraps the mux directly, innermost, because it reads the route pattern
// the mux sets: RequestID and the security middleware replace the request,
// which would hide the pattern from it.
func buildPublicHandler(logger *slog.Logger, cfg config.Config, vault secrets.Vault, views *analytics.Client) (http.Handler, error) {
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
	fileServer := http.FileServerFS(dist)
	// The file server lists a directory as an HTML page. That page is no
	// page of the site and must not be counted as "/", so any path ending in
	// a slash other than the root answers 404.
	files := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
	mux.Handle("/", files)
	// The SPA tells its pages apart by their path alone, so the server
	// answers exactly the paths App.vue knows with index.html instead of a
	// 404: /security, /r/<id> and /s/<id>. Everything else, /api/ included, stays
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
	// A secret link's page is never stored or indexed: no-store keeps it out of
	// the back/forward cache and the HTTP cache, so a Back navigation loads it
	// again instead of restoring a page that showed a secret, and noindex
	// keeps a crawler that found the address from listing it.
	mux.HandleFunc("GET /s/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex")
		index(w, r)
	})
	if err := mountLegal(mux, dist, cfg.SiteURL); err != nil {
		return nil, err
	}

	accessLog := middleware.AccessLog{ClientIP: clientIPs}
	security := middleware.DefaultSecurity()

	return middleware.Chain(views.Middleware(mux),
		middleware.Recover(logger),
		middleware.RequestID(logger),
		security.Middleware,
		accessLog.Middleware,
		secrets.NoStoreOnAPI,
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
