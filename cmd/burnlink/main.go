// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Command burnlink serves the embedded Vue build and answers
// health/readiness/metrics on govue's admin listener. It carries no
// secret-shaped configuration yet: the crypto, the store client and the
// API routes that make this a one time secret sharing service all arrive
// in a later milestone, at which point internal/config grows the store's
// address and credentials. See AGENTS.md's "Scope of this milestone".
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

	"github.com/ostendorf-cloud/burnlink/internal/config"
)

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

	publicHandler, err := buildHandler(logger)
	if err != nil {
		return err
	}

	healthRegistry := health.New()
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

// buildHandler serves the embedded SPA bundle behind govue's default
// security headers and access log. A real application adds its own API
// routes here, through its own handler-building package, once there is
// something to route to; see AGENTS.md.
func buildHandler(logger *slog.Logger) (http.Handler, error) {
	dist, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, fmt.Errorf("burnlink: %w", err)
	}

	mux := http.NewServeMux()
	files := http.FileServerFS(dist)
	mux.Handle("/", files)
	// The SPA tells its pages apart by their path alone, so the server
	// answers exactly the paths App.vue knows with index.html instead of a
	// 404: /security and /r/<id>. Everything else, /api/ included, stays
	// with the file server and answers 404 when no such file exists. A GET
	// pattern also matches HEAD. {id} spans one non-empty path segment, the
	// same shape App.vue's own /r/<id> match accepts, so /r/ and /r/a/b stay
	// 404; the API, not this route, decides whether an id exists.
	index := func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		r2.URL.RawPath = ""
		files.ServeHTTP(w, r2)
	}
	mux.HandleFunc("GET /security", index)
	mux.HandleFunc("GET /r/{id}", index)

	accessLog := middleware.AccessLog{ClientIP: clientip.NewResolver(nil)}
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
