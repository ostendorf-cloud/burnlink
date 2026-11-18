// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package redisstore is the production store.Backend: a client for any
// Redis-compatible server. The deployment runs Valkey.
//
// It sends only these commands:
//   - on every new connection, HELLO 2, with AUTH user pass attached when
//     credentials are configured (go-redis falls back to a separate AUTH on
//     a server that rejects HELLO). No CLIENT SETINFO is sent, because
//     DisableIdentity is set, and no maintenance notification handshake.
//   - SET key value PX ms NX, always PX, whatever the ttl
//   - GETDEL key
//   - PING
//   - a plain GET for store.Store's non consuming Get, which the request
//     link needs.
//
// The one time secret path (store.Secrets) uses SET NX PX and GETDEL only.
// A wrong password makes the server answer WRONGPASS, an error that does not
// contain the credential. Expiry is the server's own: this package starts no
// goroutine and runs no sweeper.
//
// The client is configured to behave predictably for a one time secret:
// RESP2, no automatic retry. A retry of GETDEL could serve a secret twice
// from the caller's view, so a failed command is reported, not repeated.
//
// Failure windows the caller must know about:
//   - GETDEL can execute on the server and the reply can still be lost, for
//     example when the read timeout fires first. The secret is then consumed
//     and the caller sees a backend error. That is refused, not served twice.
//   - SET NX can execute and its reply be lost. A manual retry of the same
//     write then gets "exists", for the caller's own earlier write.
//
// go-redis logs through one process wide logger. New replaces it once with
// an adapter to log/slog at debug level, so a failed readiness probe does
// not write an unstructured line to stderr on every probe. The change is
// global to the process, not to one Client.
package redisstore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// minTTL is the shortest lifetime the PX option can express.
const minTTL = time.Millisecond

// slogLogger adapts go-redis's logger interface to slog at debug level.
type slogLogger struct{ l func() *slog.Logger }

// Printf implements go-redis's internal Logging interface.
func (s slogLogger) Printf(ctx context.Context, format string, v ...any) {
	s.l().DebugContext(ctx, fmt.Sprintf(format, v...), "component", "go-redis")
}

var setLoggerOnce sync.Once

// quietLogger sets the process wide go-redis logger, once.
func quietLogger() {
	setLoggerOnce.Do(func() {
		redis.SetLogger(slogLogger{l: slog.Default})
	})
}

// Timeout bounds dialing, reads and writes, so an unreachable store fails a
// request or a readiness probe quickly instead of hanging it.
const timeout = 2 * time.Second

// Options is how to reach the store. The zero value of every field but Addr
// means unset.
type Options struct {
	// Addr is host:port.
	Addr string
	// Username and Password are credentials. They are never included in an
	// error returned by this package.
	Username string
	Password string
	// TLS turns on TLS with the system roots and TLS 1.2 or later.
	TLS bool
}

// Client implements store.Backend over a Redis-compatible server.
type Client struct {
	rdb *redis.Client
}

// New builds a Client. It does not connect: the first command does, so a
// store that is down at start leaves the process unready instead of dead.
func New(opts Options) (*Client, error) {
	if opts.Addr == "" {
		return nil, errors.New("redisstore: address is required")
	}
	quietLogger()
	return &Client{rdb: redis.NewClient(buildOptions(opts))}, nil
}

// buildOptions is the go-redis configuration, separate so a test can pin
// every setting that matters. MaxRetries -1 disables retries: go-redis maps
// -1 to 0 and 0 to its default of 3.
func buildOptions(opts Options) *redis.Options {
	ro := &redis.Options{
		Addr:                     opts.Addr,
		Username:                 opts.Username,
		Password:                 opts.Password,
		Protocol:                 2,
		DisableIdentity:          true,
		MaxRetries:               -1,
		DialTimeout:              timeout,
		ReadTimeout:              timeout,
		WriteTimeout:             timeout,
		MaintNotificationsConfig: &maintnotifications.Config{Mode: maintnotifications.ModeDisabled},
	}
	if opts.TLS {
		// ServerName stays empty on purpose: the dialer then verifies the
		// certificate against the host of Addr.
		ro.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return ro
}

// Close releases the connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// SetNX runs SET key value PX ms NX. The server decides atomically whether
// the key exists, so a write never overwrites. It reports whether the write
// happened.
//
// The command is built by hand because go-redis's SetNX sends EX seconds for
// a whole second ttl and PX only otherwise. A ttl below one millisecond is
// refused here: a ttl of 0 would send no expiry at all, and go-redis rounds
// 0 < ttl < 1ms up to 1ms and logs it, which would silently change the
// lifetime asked for. A ttl is truncated to whole milliseconds.
func (c *Client) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if ttl < minTTL {
		return false, errors.New("redisstore: ttl must be at least one millisecond")
	}
	err := c.rdb.Do(ctx, setNXArgs(key, value, ttl)...).Err()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, wrap("set", err)
	}
	return true, nil
}

// setNXArgs is the exact command SetNX sends.
func setNXArgs(key string, value []byte, ttl time.Duration) []any {
	return []any{"set", key, value, "px", ttl.Milliseconds(), "nx"}
}

// Get returns the value without removing it. It is the one read that does
// not consume, for a value consulted more than once before it is taken.
func (c *Client) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, wrap("get", err)
	}
	return value, true, nil
}

// GetDel runs GETDEL: it returns and removes the value in one server side
// operation, so two concurrent callers cannot both receive it.
func (c *Client) GetDel(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := c.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, wrap("getdel", err)
	}
	return value, true, nil
}

// Ping runs PING and reports whether the server answered.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return wrap("ping", err)
	}
	return nil
}

// wrap names the command and keeps the cause. This package never formats
// Options into an error; the credentials stay in Options.
func wrap(command string, err error) error {
	return fmt.Errorf("redisstore: %s: %w", command, err)
}
