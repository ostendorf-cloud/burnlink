// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package client speaks the one time secret API of internal/webapp/secrets
// from a terminal. It moves ciphertext only: the link key and the plain
// content never reach this package, see internal/payload for those.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/ostendorf-cloud/burnlink/internal/buildinfo"
	"github.com/ostendorf-cloud/burnlink/internal/payload"
)

// Why a call failed in a way the caller tells apart. Compare with errors.Is.
var (
	// ErrNotAvailable is the one answer for a secret that is gone, was
	// never issued, or was opened before. The server does not say which.
	ErrNotAvailable = errors.New("the secret is not available")
	// ErrRateLimited means the server asked the client to slow down.
	ErrRateLimited = errors.New("the server is rate limiting this client")
)

const (
	// maxJSONBytes bounds a small answer: a config, an id, an error.
	maxJSONBytes = 64 << 10
	// maxOpenBytes bounds the open answer. The server caps a ciphertext at
	// 64 MiB, which is 4/3 of that as base64 plus the JSON around it.
	maxOpenBytes = 96 << 20
)

// APIError is an error answer of the server in its own shape.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server answered %d %s: %s", e.Status, e.Code, e.Message)
}

// Config is what the server accepts, from GET /api/v1/config.
type Config struct {
	MaxCiphertextBytes int
	LifetimeMin        time.Duration
	LifetimeMax        time.Duration
	LifetimeDefault    time.Duration
}

// Stored is what the server answers to a stored secret.
type Stored struct {
	ID        string
	ExpiresAt time.Time
}

// Client is a connection to one server.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a client for the server at origin, for example
// https://burnlink.de. A nil hc gets a client that never follows a redirect:
// a redirected POST would hand the ciphertext to a second host.
func New(origin string, hc *http.Client) (*Client, error) {
	base, err := parseOrigin(origin)
	if err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{}
	}
	// Whatever the caller passed, a redirect is an answer, not a detour.
	checked := *hc
	checked.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base, http: &checked}, nil
}

func parseOrigin(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, errors.New("server is not a valid URL")
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, errors.New("server must start with https:// or http://")
	case u.Hostname() == "":
		return nil, errors.New("server has no host")
	case u.User != nil:
		return nil, errors.New("server must not carry a user name or password")
	case u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return nil, errors.New("server must be an origin: scheme, host and port only")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// Origin returns the server this client talks to.
func (c *Client) Origin() string { return c.base.String() }

// Link builds the URL a sender shares. The key travels in the fragment only,
// which no client sends to a server.
func (c *Client) Link(id string, linkKey []byte) string {
	return c.base.String() + "/s/" + url.PathEscape(id) + "#" + payload.EncodeBase64URL(linkKey)
}

// Config reads the limits of the server.
func (c *Client) Config(ctx context.Context) (Config, error) {
	var resp struct {
		MaxCiphertextBytes int `json:"maxCiphertextBytes"`
		Lifetime           struct {
			MinSeconds     int64 `json:"minSeconds"`
			MaxSeconds     int64 `json:"maxSeconds"`
			DefaultSeconds int64 `json:"defaultSeconds"`
		} `json:"lifetime"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/config", nil, &resp, maxJSONBytes); err != nil {
		return Config{}, err
	}
	return Config{
		MaxCiphertextBytes: resp.MaxCiphertextBytes,
		LifetimeMin:        time.Duration(resp.Lifetime.MinSeconds) * time.Second,
		LifetimeMax:        time.Duration(resp.Lifetime.MaxSeconds) * time.Second,
		LifetimeDefault:    time.Duration(resp.Lifetime.DefaultSeconds) * time.Second,
	}, nil
}

// Store uploads ciphertext. A lifetime of zero leaves the choice to the
// server.
func (c *Client) Store(ctx context.Context, ciphertext []byte, lifetime time.Duration) (Stored, error) {
	body := struct {
		Ciphertext      string `json:"ciphertext"`
		LifetimeSeconds *int64 `json:"lifetimeSeconds,omitempty"`
	}{Ciphertext: payload.EncodeBase64(ciphertext)}
	if lifetime > 0 {
		seconds := int64(lifetime / time.Second)
		body.LifetimeSeconds = &seconds
	}
	var resp struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/secrets", body, &resp, maxJSONBytes); err != nil {
		return Stored{}, err
	}
	if resp.ID == "" || strings.ContainsAny(resp.ID, "/?#") {
		return Stored{}, errors.New("server answered without a usable id")
	}
	return Stored{ID: resp.ID, ExpiresAt: resp.ExpiresAt}, nil
}

// Open reads and deletes the secret. The server removes it in the same step,
// so a caller that loses the answer cannot ask again.
func (c *Client) Open(ctx context.Context, id string) ([]byte, error) {
	var resp struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/secrets/"+url.PathEscape(id)+"/open", struct{}{}, &resp, maxOpenBytes); err != nil {
		return nil, err
	}
	ciphertext, err := payload.DecodeBase64(resp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("server answered with a ciphertext that is not base64: %w", err)
	}
	return ciphertext, nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, limit int64) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "burnlink-cli/"+buildinfo.Read().Version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the URL, which carries an id on the open path.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("reach %s: %w", c.base.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return readError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	if int64(len(data)) > limit {
		return errors.New("server answer is larger than any secret can be")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("server answer is not the JSON this client expects")
	}
	return nil
}

// readError turns a non 2xx answer into an error. The server's own words are
// someone else's text: control characters go, and the length is capped.
func readError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotAvailable
	case http.StatusTooManyRequests:
		return ErrRateLimited
	}
	apiErr := &APIError{Status: resp.StatusCode, Code: "unknown", Message: http.StatusText(resp.StatusCode)}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBytes))
	if err != nil {
		return apiErr
	}
	var shape struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &shape) == nil {
		if code := printable(shape.Error.Code, 64); code != "" {
			apiErr.Code = code
		}
		if msg := printable(shape.Error.Message, 200); msg != "" {
			apiErr.Message = msg
		}
	}
	return apiErr
}

func printable(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Link is a secret link taken apart.
type Link struct {
	Origin string
	ID     string
	Key    []byte
}

// ParseLink reads /s/<id>#<key>. The key has to be exactly keyBytes of
// canonical base64url, so a mangled link is told apart from a failed
// decryption before the server is asked, and so before the secret is spent.
func ParseLink(raw string, keyBytes int) (Link, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Link{}, errors.New("the link is not a valid URL")
	}
	origin, err := parseOrigin((&url.URL{Scheme: u.Scheme, Host: u.Host, User: u.User}).String())
	if err != nil {
		return Link{}, fmt.Errorf("the link: %w", err)
	}
	id, ok := strings.CutPrefix(u.EscapedPath(), "/s/")
	if !ok || id == "" || strings.Contains(id, "/") || u.RawQuery != "" {
		return Link{}, errors.New("the link must look like https://host/s/<id>#<key>")
	}
	if id, err = url.PathUnescape(id); err != nil || id == "" || strings.ContainsAny(id, "/?#") {
		return Link{}, errors.New("the link has an id this client cannot use")
	}
	if u.Fragment == "" {
		return Link{}, errors.New("the link is missing its key: use it exactly as it was shared, including everything after the #")
	}
	key, err := payload.DecodeBase64URL(u.Fragment)
	if err != nil || len(key) != keyBytes {
		return Link{}, errors.New("the link carries a key of the wrong form: use it exactly as it was shared, including everything after the #")
	}
	return Link{Origin: origin.String(), ID: id, Key: key}, nil
}
