// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package secrets serves the five endpoints of a one time secret link: store
// a ciphertext, ask whether it is still there, open and delete it in one
// step, report the limits the page has to enforce, and report the running
// build. docs/concepts/burnlink.md is the contract.
//
// The server handles opaque bytes. It never sees a key and never looks inside
// a ciphertext. Every link it will not serve, whether unknown, expired,
// already opened or malformed, gets one answer, see refuse.
package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/ostendorf-cloud/govue/api"
	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/csrf"
	"github.com/ostendorf-cloud/govue/logging"
	"github.com/ostendorf-cloud/govue/middleware"
	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/buildinfo"
	"github.com/ostendorf-cloud/burnlink/internal/store"
)

// Routes. A secret's id is the last or the second to last path segment.
const (
	pathSecrets = "/api/v1/secrets"
	pathConfig  = "/api/v1/config"
	pathVersion = "/api/v1/version"
)

// jsonOverhead is the room the JSON envelope around the base64 ciphertext
// needs on top of the base64 text itself. It is sized for compact JSON as
// JSON.stringify writes it. A client that escapes every "/" as "\/", which
// is PHP's default, adds a byte per slash and can see a ciphertext close to
// the size limit refused with 413. The page is not affected.
const jsonOverhead = 1024

// NoStoreOnAPI sets Cache-Control: no-store on every request whose cleaned
// path is under /api/, before the mux runs. The mux answers a path it has to
// clean (a double slash, a dot segment) with a redirect of its own, which no
// route wrapper ever sees. It belongs directly around the mux.
func NoStoreOnAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := path.Clean("/" + r.URL.Path); p == "/api" || strings.HasPrefix(p, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// Vault is what the handlers need from the secret store. *store.Secrets is
// the production implementation.
type Vault interface {
	Put(ctx context.Context, id string, ciphertext []byte, ttl time.Duration) error
	Take(ctx context.Context, id string) ([]byte, error)
	Exists(ctx context.Context, id string) (bool, error)
}

var _ Vault = (*store.Secrets)(nil)

// Config is everything New needs. Every field except Now and Build is
// required.
type Config struct {
	Vault Vault
	// MaxBytes is the largest ciphertext accepted, decoded.
	MaxBytes int
	// LifetimeMin, LifetimeMax and LifetimeDefault bound the lifetime a
	// sender may ask for and name the one used when none is asked for.
	LifetimeMin     time.Duration
	LifetimeMax     time.Duration
	LifetimeDefault time.Duration
	// Limiter is the per client address budget shared by the three secret
	// endpoints. ClientIP resolves that address; the trusted proxy ranges
	// live in it.
	Limiter  *ratelimit.Limiter
	ClientIP *clientip.Resolver
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Build reports the running build. Defaults to buildinfo.Read.
	Build func() buildinfo.Info
}

// Handler answers the secret endpoints. Build it with New.
type Handler struct {
	cfg  Config
	rate func(http.Handler) http.Handler
	csrf *csrf.Protector
}

// New validates cfg and returns a Handler.
func New(cfg Config) (*Handler, error) {
	switch {
	case cfg.Vault == nil:
		return nil, errors.New("secrets: vault is required")
	case cfg.Limiter == nil || cfg.ClientIP == nil:
		return nil, errors.New("secrets: limiter and client address resolver are required")
	case cfg.MaxBytes < 1:
		return nil, errors.New("secrets: max bytes must be positive")
	case cfg.LifetimeMin < time.Second || cfg.LifetimeMin > cfg.LifetimeMax ||
		cfg.LifetimeDefault < cfg.LifetimeMin || cfg.LifetimeDefault > cfg.LifetimeMax:
		return nil, errors.New("secrets: lifetimes must satisfy 1s <= min <= default <= max")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Build == nil {
		cfg.Build = buildinfo.Read
	}

	limit, err := middleware.NewRateLimit(middleware.RateLimitConfig{Limiter: cfg.Limiter, ClientIP: cfg.ClientIP})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}

	// No session exists, so there is no token to check: the protector
	// contributes the cross site refusal, based on the browser's own
	// Sec-Fetch-Site and Origin signals, and nothing else.
	protector, err := csrf.New(func(*http.Request) (string, bool) { return "", false })
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	protector.OnRefusal(func(w http.ResponseWriter, r *http.Request, cause error) {
		logging.FromContext(r.Context()).DebugContext(r.Context(), "request refused", "error", cause.Error())
		api.WriteError(w, r, api.PermissionDenied("cross site request refused"))
	})

	return &Handler{cfg: cfg, rate: limit.Middleware, csrf: protector}, nil
}

// Register wires every endpoint onto mux.
//
//	POST /api/v1/secrets               store a ciphertext, answers 201 with the id
//	HEAD /api/v1/secrets/{id}          is it still there, 200 or the refusal, never consumes
//	POST /api/v1/secrets/{id}/open     read and delete in one step
//	GET  /api/v1/config                the limits the page enforces
//	GET  /api/v1/version               the running build
//
// Every other request under /api/v1/secrets/ gets the refusal, whatever the
// method and the path, so a malformed id has no route of its own to give it
// away. Anything else under /api/ gets a JSON 404.
func (h *Handler) Register(mux *http.ServeMux) {
	unsafe := func(f api.HandlerFunc) http.Handler {
		return noStore(h.rate(h.csrf.Middleware(requireJSON(api.Handle(f)))))
	}

	mux.Handle("POST "+pathSecrets, unsafe(h.store))
	mux.Handle("POST "+pathSecrets+"/{id}/open", unsafe(h.open))
	mux.Handle("HEAD "+pathSecrets+"/{id}", noStore(h.rate(api.Handle(h.check))))
	// Without its own pattern the bare collection path would be redirected
	// by the mux to the subtree below, and the redirect carries no no-store.
	mux.Handle(pathSecrets, noStore(api.NotFoundHandler()))
	mux.Handle(pathSecrets+"/", noStore(h.rate(http.HandlerFunc(h.refuse))))
	mux.Handle("GET "+pathConfig, noStore(api.Handle(h.config)))
	mux.Handle("GET "+pathVersion, noStore(api.Handle(h.version)))
	mux.Handle("/api/", noStore(api.NotFoundHandler()))
}

// noStore keeps every answer, refusals and errors included, out of every
// cache. api.Write sets it too; this covers the answers api does not write.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireJSON answers 415 unless the request names application/json. govue's
// own decoder accepts a missing Content-Type, which a state changing
// endpoint must not: a request a browser can send without a preflight,
// such as a form post, carries none of the JSON types.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			api.WriteError(w, r, api.New(http.StatusUnsupportedMediaType, api.CodeUnsupportedMediaType,
				"content type must be application/json"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuse is the one answer for every link the service will not serve.
//
// It is a fixed status and a fixed body, in govue's error shape. The body is
// written without the request id the shape usually carries: that id differs
// per request, so it would make every refusal byte for byte unique. Nothing
// about the id, the cause or the store reaches the body, a header or the
// log.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request) {
	api.WriteError(w, r.WithContext(context.Background()), api.NotFound("secret not available"))
}

// lookupID is the id the store is asked about. A malformed id is replaced by
// dummyID, which is well formed and never issued, so the store round trip
// happens either way and the refusal does not arrive measurably earlier.
func lookupID(id string) string {
	if validID(id) {
		return id
	}
	return dummyID
}

type storeRequest struct {
	// Ciphertext is the standard base64 encoding of the opaque payload.
	Ciphertext string `json:"ciphertext"`
	// LifetimeSeconds is optional; the default lifetime applies without it.
	LifetimeSeconds *int64 `json:"lifetimeSeconds"`
}

type storeResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// store keeps a ciphertext for the lifetime asked for, within the limits.
func (h *Handler) store(w http.ResponseWriter, r *http.Request) error {
	// The size limit applies while the body is read, so an oversized
	// request is never held in memory. The envelope limit covers the base64
	// expansion of a ciphertext of exactly MaxBytes plus the JSON around it;
	// the decoded length is checked exactly below.
	envelope := int64((h.cfg.MaxBytes+2)/3)*4 + jsonOverhead
	var req storeRequest
	if err := api.DecodeLimit(r, &req, envelope); err != nil {
		return err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return api.Invalid("ciphertext must be non empty standard base64")
	}
	if len(ciphertext) > h.cfg.MaxBytes {
		return api.New(http.StatusRequestEntityTooLarge, api.CodeRequestTooLarge,
			fmt.Sprintf("ciphertext must be at most %d bytes", h.cfg.MaxBytes))
	}

	lifetime := h.cfg.LifetimeDefault
	if req.LifetimeSeconds != nil {
		seconds := *req.LifetimeSeconds
		// Compared as seconds first so a huge value cannot overflow the
		// duration it is converted to.
		if seconds < int64(h.cfg.LifetimeMin/time.Second) || seconds > int64(h.cfg.LifetimeMax/time.Second) {
			return api.Invalid(fmt.Sprintf("lifetimeSeconds must be between %d and %d",
				int64(h.cfg.LifetimeMin/time.Second), int64(h.cfg.LifetimeMax/time.Second)))
		}
		lifetime = time.Duration(seconds) * time.Second
	}

	id, err := NewID()
	if err != nil {
		return api.Internal(err)
	}
	if err := h.cfg.Vault.Put(r.Context(), id, ciphertext, lifetime); err != nil {
		// ErrExists included: a collision of 128 random bits is a bug, not
		// a condition to paper over with a retry.
		return api.Internal(fmt.Errorf("secrets: store: %w", err))
	}
	return api.Write(w, http.StatusCreated, storeResponse{ID: id, ExpiresAt: h.cfg.Now().Add(lifetime).UTC()})
}

// check answers whether the secret is still there. It never takes it, and
// every refusal is the one refusal.
func (h *Handler) check(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	found, err := h.cfg.Vault.Exists(r.Context(), lookupID(id))
	if err != nil {
		return api.Internal(fmt.Errorf("secrets: check: %w", err))
	}
	if !found || !validID(id) {
		h.refuse(w, r)
		return nil
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

type openResponse struct {
	// Ciphertext is the standard base64 encoding of the stored payload.
	Ciphertext string `json:"ciphertext"`
}

// open hands the ciphertext out and deletes it in one store operation, so of
// any number of concurrent readers exactly one is served.
func (h *Handler) open(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	ciphertext, err := h.cfg.Vault.Take(r.Context(), lookupID(id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.refuse(w, r)
		return nil
	case err != nil:
		return api.Internal(fmt.Errorf("secrets: open: %w", err))
	case !validID(id):
		// Unreachable unless dummyID was ever stored. Still the refusal.
		h.refuse(w, r)
		return nil
	}
	return api.Write(w, http.StatusOK, openResponse{Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)})
}

type configResponse struct {
	// MaxCiphertextBytes is the largest ciphertext, decoded, the server
	// accepts.
	MaxCiphertextBytes int            `json:"maxCiphertextBytes"`
	Lifetime           lifetimeLimits `json:"lifetime"`
}

type lifetimeLimits struct {
	MinSeconds     int64 `json:"minSeconds"`
	MaxSeconds     int64 `json:"maxSeconds"`
	DefaultSeconds int64 `json:"defaultSeconds"`
}

// config reports what the page has to enforce before it sends anything.
func (h *Handler) config(w http.ResponseWriter, _ *http.Request) error {
	return api.Write(w, http.StatusOK, configResponse{
		MaxCiphertextBytes: h.cfg.MaxBytes,
		Lifetime: lifetimeLimits{
			MinSeconds:     int64(h.cfg.LifetimeMin / time.Second),
			MaxSeconds:     int64(h.cfg.LifetimeMax / time.Second),
			DefaultSeconds: int64(h.cfg.LifetimeDefault / time.Second),
		},
	})
}

// version reports the running build.
func (h *Handler) version(w http.ResponseWriter, _ *http.Request) error {
	return api.Write(w, http.StatusOK, h.cfg.Build())
}
