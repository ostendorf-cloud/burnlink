// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package requestlink

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/ostendorf-cloud/govue/api"
	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/ratelimit"

	"github.com/ostendorf-cloud/burnlink/internal/store"
)

// requestJSONMaxBytes bounds the JSON body api.DecodeLimit accepts for a
// submission whose sealed payload may be up to maxSubmissionBytes, ahead of
// the base64-decoded payload's own check: base64 and the surrounding JSON
// both add overhead, so this limit has to leave room for that rather than
// matching maxSubmissionBytes exactly. It is computed from the link's own
// configured limit, never the package default, so a deployment that raises
// MaxSubmissionBytes above DefaultMaxSubmissionBytes can actually accept a
// payload that size instead of having the JSON envelope reject it first.
func requestJSONMaxBytes(maxSubmissionBytes int) int64 {
	return int64((maxSubmissionBytes*4)/3) + 4096
}

// Handler answers the request link's own endpoints: create a link, submit a
// sealed payload to it, and open everything waiting for the owner. It holds
// no secret-shaped state of its own; Store is where everything it reads or
// writes actually lives.
type Handler struct {
	Store store.Store
	// Now returns the current time. Defaults to time.Now; tests override it
	// to control expiry without sleeping.
	Now func() time.Time
	// ClientIP resolves the address a submission is rate limited by.
	ClientIP *clientip.Resolver
	// SubmitLimiter is the token bucket a submission to one link from one
	// resolved address draws from. Keyed by link id and address together,
	// so one abusive sender cannot exhaust another sender's share of the
	// same link; see submitLimitKey.
	SubmitLimiter *ratelimit.Limiter
	// LookupLimiter is the token bucket an owner open or an info call to one
	// link from one resolved address draws from, keyed like SubmitLimiter.
	// It is drawn before the store is read. The key carries the id, so a
	// caller that varies the id gets a fresh bucket and a read each time.
	LookupLimiter *ratelimit.Limiter
	// CreateLimiter is the token bucket a link creation from one resolved
	// address draws from. There is no link id yet, so it is keyed by the
	// address alone.
	CreateLimiter *ratelimit.Limiter

	Lifetime           time.Duration
	MaxSubmissionBytes int
	// MaxConcurrentSubmissions is how many submissions one request link
	// holds waiting at once, not a lifetime total: see
	// Metadata.MaxConcurrentSubmissions for why opening frees a slot back
	// up for a later submission.
	MaxConcurrentSubmissions int
}

// NewHandler returns a Handler over s with every placeholder default from
// this package applied, ready to Register. A caller overrides only the
// fields it needs to.
//
// trustedProxies is forwarded to clientip.NewResolver unchanged: empty
// trusts no proxy and resolves every client address as the TCP peer, which
// is wrong behind the chart's own Ingress, where every submitter would
// otherwise collapse onto the ingress pod's address and the per-address
// rate limit below would collapse into one global bucket. A caller behind a
// reverse proxy passes the proxy's own address ranges, typically
// internal/config's own TrustedProxies once this handler is wired into
// cmd/burnlink; see AGENTS.md's "Scope of this milestone".
func NewHandler(s store.Store, trustedProxies []netip.Prefix) *Handler {
	return &Handler{
		Store:                    s,
		Now:                      time.Now,
		ClientIP:                 clientip.NewResolver(trustedProxies),
		SubmitLimiter:            ratelimit.New(DefaultSubmitBurst, DefaultSubmitPer, 10_000),
		LookupLimiter:            ratelimit.New(DefaultLookupBurst, DefaultLookupPer, 10_000),
		CreateLimiter:            ratelimit.New(DefaultCreateBurst, DefaultCreatePer, 10_000),
		Lifetime:                 DefaultLifetime,
		MaxSubmissionBytes:       DefaultMaxSubmissionBytes,
		MaxConcurrentSubmissions: DefaultMaxConcurrentSubmissions,
	}
}

// Register wires every endpoint onto mux, under /api/v1: govue's own
// createClient defaults to that base path, and there is no reason for this
// service's first API routes to pick a different one.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/request-links", api.Handle(h.create))
	mux.Handle("GET /api/v1/request-links/{id}", api.Handle(h.info))
	mux.Handle("POST /api/v1/request-links/{id}/submissions", api.Handle(h.submit))
	mux.Handle("POST /api/v1/request-links/{id}/open", api.Handle(h.open))
}

func (h *Handler) clock() time.Time {
	if h.Now == nil {
		return time.Now()
	}
	return h.Now()
}

type createRequest struct {
	// OwnerAuthHash is base64 standard encoding of SHA-256 of the owner
	// auth value, never the value itself. See Metadata.OwnerAuthHash.
	OwnerAuthHash string `json:"ownerAuthHash"`
}

type createResponse struct {
	ID                       string    `json:"id"`
	ExpiresAt                time.Time `json:"expiresAt"`
	MaxSubmissionBytes       int       `json:"maxSubmissionBytes"`
	MaxConcurrentSubmissions int       `json:"maxConcurrentSubmissions"`
}

// create stores a new request link's metadata and returns its id. The
// owner's public key never reaches this handler at all: docs/adr/0003
// settles that it travels only in the link's own fragment.
func (h *Handler) create(w http.ResponseWriter, r *http.Request) error {
	if allowed, wait := h.CreateLimiter.Take(clientip.Key(h.ClientIP.Resolve(r))); !allowed {
		return api.TooManyRequests(wait)
	}

	var req createRequest
	if err := api.Decode(r, &req); err != nil {
		return err
	}

	ownerAuthHash, err := base64.StdEncoding.DecodeString(req.OwnerAuthHash)
	if err != nil || len(ownerAuthHash) != ownerAuthBytes {
		return api.Invalid("ownerAuthHash must be the base64 encoding of a 32 byte SHA-256 digest")
	}

	id, err := NewID()
	if err != nil {
		return api.Internal(err)
	}

	metadata := Metadata{
		ExpiresAt:                h.clock().Add(h.Lifetime),
		MaxSubmissionBytes:       h.MaxSubmissionBytes,
		MaxConcurrentSubmissions: h.MaxConcurrentSubmissions,
		OwnerAuthHash:            ownerAuthHash,
	}
	encoded, err := marshalMetadata(metadata)
	if err != nil {
		return api.Internal(err)
	}

	ok, err := h.Store.SetNX(r.Context(), metadataKey(id), encoded, h.Lifetime)
	if err != nil {
		return api.Internal(fmt.Errorf("requestlink: create: %w", err))
	}
	if !ok {
		// idBytes is 16 random bytes; a collision is not expected in
		// practice. Reported as a conflict rather than retried silently, so
		// a real collision is never papered over.
		return api.Conflict("request link id already in use, try again")
	}

	return api.Write(w, http.StatusCreated, createResponse{
		ID:                       id,
		ExpiresAt:                metadata.ExpiresAt,
		MaxSubmissionBytes:       metadata.MaxSubmissionBytes,
		MaxConcurrentSubmissions: metadata.MaxConcurrentSubmissions,
	})
}

type submitRequest struct {
	// Payload is base64 standard encoding of the sealed submission; see
	// web/src/lib/request-link-crypto.ts.
	Payload string `json:"payload"`
}

// submit accepts one sealed submission for the link id names, enforcing
// its lifetime, size limit, rate limit and concurrent submission limit.
// Reaching this handler never requires the owner's private key, or any key
// at all: the server stores the ciphertext it is handed and cannot read it.
func (h *Handler) submit(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")

	metadata, found, err := h.getMetadata(r.Context(), id)
	if err != nil {
		return err
	}
	if !found {
		return api.NotFound("request link not found")
	}

	if allowed, wait := h.SubmitLimiter.Take(submitLimitKey(id, h.ClientIP.Resolve(r))); !allowed {
		return api.TooManyRequests(wait)
	}

	var req submitRequest
	if err := api.DecodeLimit(r, &req, requestJSONMaxBytes(metadata.MaxSubmissionBytes)); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		return api.Invalid("payload must be base64 encoded")
	}
	if len(payload) > metadata.MaxSubmissionBytes {
		return api.New(http.StatusRequestEntityTooLarge, api.CodeRequestTooLarge,
			fmt.Sprintf("payload must be at most %d bytes", metadata.MaxSubmissionBytes))
	}

	ttl := metadata.ExpiresAt.Sub(h.clock())
	if ttl <= 0 {
		return api.NotFound("request link not found")
	}

	for slot := 0; slot < metadata.MaxConcurrentSubmissions; slot++ {
		ok, err := h.Store.SetNX(r.Context(), slotKey(id, slot), payload, ttl)
		if err != nil {
			return api.Internal(fmt.Errorf("requestlink: submit: %w", err))
		}
		if ok {
			api.NoContent(w)
			return nil
		}
	}
	return api.Conflict("this request link already holds as many submissions waiting as it accepts at once")
}

type infoResponse struct {
	ExpiresAt          time.Time `json:"expiresAt"`
	MaxSubmissionBytes int       `json:"maxSubmissionBytes"`
}

// info returns the limits a submitter needs before choosing what to send: the
// largest sealed payload and the link's expiry. It reveals nothing submit
// would not already reveal to anyone holding the id.
func (h *Handler) info(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")

	if allowed, wait := h.LookupLimiter.Take(submitLimitKey(id, h.ClientIP.Resolve(r))); !allowed {
		return api.TooManyRequests(wait)
	}

	metadata, found, err := h.getMetadata(r.Context(), id)
	if err != nil {
		return err
	}
	if !found {
		return api.NotFound("request link not found")
	}
	return api.Write(w, http.StatusOK, infoResponse{
		ExpiresAt:          metadata.ExpiresAt,
		MaxSubmissionBytes: metadata.MaxSubmissionBytes,
	})
}

type openRequest struct {
	// OwnerAuth is base64 standard encoding of the value only the holder of
	// the owner's private key can derive; see Metadata.OwnerAuthHash.
	OwnerAuth string `json:"ownerAuth"`
}

type openResponse struct {
	// Submissions is base64 standard encoding of every sealed submission
	// that had arrived, each already removed from the store by this call.
	Submissions []string `json:"submissions"`
}

// open returns and removes every submission currently waiting on the
// request link id names. It is reachable by anyone who knows id, exactly
// like the submit endpoint; what tells the owner's own call apart is
// ownerAuth, which only the private key holder can reproduce. The body is
// decoded before the link is looked up, so a well formed request with a wrong
// value answers exactly like one for an unknown link; a malformed body is
// refused the same way for both.
func (h *Handler) open(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")

	if allowed, wait := h.LookupLimiter.Take(submitLimitKey(id, h.ClientIP.Resolve(r))); !allowed {
		return api.TooManyRequests(wait)
	}

	var req openRequest
	if err := api.Decode(r, &req); err != nil {
		return err
	}
	ownerAuth, err := base64.StdEncoding.DecodeString(req.OwnerAuth)
	if err != nil {
		return api.Invalid("ownerAuth must be base64 encoded")
	}

	metadata, found, err := h.getMetadata(r.Context(), id)
	if err != nil {
		return err
	}
	if !found {
		return api.NotFound("request link not found")
	}
	if !ownerAuthMatches(ownerAuth, metadata.OwnerAuthHash) {
		return api.NotFound("request link not found")
	}

	submissions := make([]string, 0, metadata.MaxConcurrentSubmissions)
	for slot := 0; slot < metadata.MaxConcurrentSubmissions; slot++ {
		value, ok, err := h.Store.GetDel(r.Context(), slotKey(id, slot))
		if err != nil {
			return api.Internal(fmt.Errorf("requestlink: open: %w", err))
		}
		if ok {
			submissions = append(submissions, base64.StdEncoding.EncodeToString(value))
		}
	}

	return api.Write(w, http.StatusOK, openResponse{Submissions: submissions})
}

// getMetadata reads and decodes id's metadata, treating a link whose
// recorded expiry has passed as not found even if the store has not yet
// evicted its key: see Metadata.ExpiresAt.
func (h *Handler) getMetadata(ctx context.Context, id string) (Metadata, bool, error) {
	raw, found, err := h.Store.Get(ctx, metadataKey(id))
	if err != nil {
		return Metadata{}, false, api.Internal(fmt.Errorf("requestlink: read metadata: %w", err))
	}
	if !found {
		return Metadata{}, false, nil
	}
	metadata, err := unmarshalMetadata(raw)
	if err != nil {
		return Metadata{}, false, api.Internal(err)
	}
	if !metadata.ExpiresAt.After(h.clock()) {
		return Metadata{}, false, nil
	}
	return metadata, true, nil
}

// submitLimitKey keys a per link rate limiter (submit, open and info) by link
// and by resolved address together, so one abusive sender cannot exhaust
// another sender's share of the same link's budget.
func submitLimitKey(id string, addr netip.Addr) string {
	return id + "|" + clientip.Key(addr)
}
