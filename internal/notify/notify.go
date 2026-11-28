// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package notify tells a sender, through a webhook, that their link was
// redeemed.
//
// The webhook URL is chosen by an anonymous sender, so every request to it
// is a request to an untrusted destination. The package is built around
// that: see Validate for the checks at store time and guardControl for the
// check at connect time, and the constants below for the bounds. A
// notification is best effort. It never blocks and never reverses the
// redemption that triggers it.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// The retry and timeout decisions. AGENTS.md records them; change both
// together.
const (
	// attemptTimeout bounds one attempt: connecting, the TLS handshake,
	// sending the request and reading the response head.
	attemptTimeout = 5 * time.Second
	// totalTimeout bounds the whole delivery, attempts and waits together.
	totalTimeout = 20 * time.Second
	// maxAttempts is the first attempt plus two retries.
	maxAttempts = 3
	// maxInFlight bounds the deliveries running at once. A redemption that
	// finds the limit reached is not notified.
	maxInFlight = 32
	// maxResponseBytes is the most of a response body that is read. The
	// body is discarded and never looked at.
	maxResponseBytes = 4 << 10
	// maxHeaderBytes bounds the response headers.
	maxHeaderBytes = 8 << 10
)

// backoff is the wait before retry n, indexed from zero.
var backoff = [maxAttempts - 1]time.Duration{time.Second, 4 * time.Second}

// Body is the whole request body of a notification. It holds the id and the
// time and nothing else. It has no field for the payload and the notifier
// never sees one.
type Body struct {
	ID         string    `json:"id"`
	RedeemedAt time.Time `json:"redeemedAt"`
}

// Config is what New needs.
type Config struct {
	// Logger receives one line for a notification that was given up, with no
	// URL, no host and no id in it.
	Logger *slog.Logger
	// Transport replaces the guarded transport. Tests only: production code
	// never sets it, and a notifier given one has no connect time guard.
	Transport http.RoundTripper
	// Sleep replaces the wait between attempts. Tests only. It returns early
	// with the context's error when ctx ends.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Notifier delivers notifications in the background. Build it with New and
// call Close on shutdown.
type Notifier struct {
	log    *slog.Logger
	client *http.Client
	sleep  func(ctx context.Context, d time.Duration) error
	slots  chan struct{}

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// New returns a Notifier whose client refuses every destination Validate and
// the connect time guard refuse, ignores the proxy environment, and follows
// no redirect.
func New(cfg Config) *Notifier {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	rt := cfg.Transport
	if rt == nil {
		dialer := &net.Dialer{Timeout: attemptTimeout, Control: guardControl}
		rt = &http.Transport{
			// Never the proxy of the environment: a proxy would connect on
			// the guard's behalf, to an address it never sees.
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    attemptTimeout,
			ResponseHeaderTimeout:  attemptTimeout,
			MaxResponseHeaderBytes: maxHeaderBytes,
			DisableKeepAlives:      true,
		}
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	return &Notifier{
		log: logger,
		client: &http.Client{
			Transport: rt,
			Timeout:   attemptTimeout,
			// A redirect is never followed, so a destination cannot hand the
			// request on to an address the guard has not seen. A 3xx answer
			// is a failed delivery.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sleep: sleep,
		slots: make(chan struct{}, maxInFlight),
	}
}

// Validate is the package function of that name, as a method so the
// handler's consumer interface needs one value.
func (*Notifier) Validate(raw string) error { return Validate(raw) }

// Notify delivers the notification for id in the background and returns at
// once. It never fails: a delivery that does not succeed is logged and
// dropped. The delivery does not end with ctx, it ends with its own bounds,
// because the request that redeemed the secret ends first.
func (n *Notifier) Notify(ctx context.Context, id string, redeemedAt time.Time, target string) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	select {
	case n.slots <- struct{}{}:
	default:
		n.mu.Unlock()
		n.log.WarnContext(ctx, "pickup notification dropped", "reason", "too many in flight")
		return
	}
	n.wg.Add(1)
	n.mu.Unlock()

	body := Body{ID: id, RedeemedAt: redeemedAt.UTC()}
	bg := context.WithoutCancel(ctx)
	go func() {
		defer n.wg.Done()
		defer func() { <-n.slots }()
		dctx, cancel := context.WithTimeout(bg, totalTimeout)
		defer cancel()
		if err := n.deliver(dctx, target, body); err != nil {
			n.log.WarnContext(dctx, "pickup notification given up", "reason", reason(err))
		}
	}()
}

// Close stops accepting notifications and waits for the running ones until
// ctx ends. A delivery still running then ends with its own bounds.
func (n *Notifier) Close(ctx context.Context) error {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("notify: close: %w", ctx.Err())
	}
}

// errPermanent marks a failure no retry can change.
var errPermanent = errors.New("notify: permanent failure")

// deliver sends body to target, with up to maxAttempts attempts. The target
// is checked again with Validate: it came out of the store, and every store
// time check stays in force at delivery.
func (n *Notifier) deliver(ctx context.Context, target string, body Body) error {
	if err := Validate(target); err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}

	var last error
	for attempt := range maxAttempts {
		if attempt > 0 {
			if err := n.sleep(ctx, backoff[attempt-1]); err != nil {
				return err
			}
		}
		last = n.attempt(ctx, target, raw)
		if last == nil || errors.Is(last, errPermanent) {
			return last
		}
	}
	return last
}

// attempt makes one request. A failure that retrying cannot change wraps
// errPermanent.
func (n *Notifier) attempt(ctx context.Context, target string, raw []byte) error {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "burnlink-notify")

	resp, err := n.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return fmt.Errorf("%w: %w", errPermanent, ErrBlocked)
		}
		// Not the URL: the error of a failed Do names it.
		return errTransport
	}
	defer func() { _ = resp.Body.Close() }()
	// The body is read only to let the connection end cleanly, and only up
	// to a bound.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 500, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusRequestTimeout:
		return errStatus
	default:
		// Includes every 3xx: a redirect is refused, not followed.
		return fmt.Errorf("%w: %w", errPermanent, errStatus)
	}
}

var (
	errTransport = errors.New("notify: request failed")
	errStatus    = errors.New("notify: unexpected status")
)

// reason names a failure for the log in a fixed vocabulary.
func reason(err error) string {
	switch {
	case errors.Is(err, ErrBlocked):
		return "destination not allowed"
	case errors.Is(err, ErrInvalidTarget):
		return "invalid url"
	case errors.Is(err, errStatus):
		return "unexpected status"
	case errors.Is(err, errTransport):
		return "request failed"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timed out"
	default:
		return "failed"
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
