// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package redisstore is the production store.Backend: a client for any
// Redis-compatible server. The deployment runs Dragonfly.
//
// It sends only these commands: AUTH when credentials are configured,
// SET key value PX ms NX, GETDEL key, PING, and a plain GET for
// store.Store's non consuming Get, which the request link needs. The
// one time secret path (store.Secrets) uses SET NX PX and GETDEL only.
// Expiry is the server's own: this package starts no goroutine and runs no
// sweeper.
//
// The client is configured to behave predictably for a one time secret:
// RESP2, no CLIENT SETINFO or maintenance notification handshake, and no
// automatic retry. A retried command could hide a failure the caller has to
// see, and a secret that cannot be read is better refused than guessed at.
package redisstore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// minTTL is the shortest lifetime the PX option can express.
const minTTL = time.Millisecond

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
		ro.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Client{rdb: redis.NewClient(ro)}, nil
}

// Close releases the connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// SetNX runs SET key value PX ms NX. The server decides atomically whether
// the key exists, so a write never overwrites. It reports whether the write
// happened. A ttl below one millisecond is refused: it would otherwise
// become a key with no lifetime, or a server error.
func (c *Client) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if ttl < minTTL {
		return false, errors.New("redisstore: ttl must be at least one millisecond")
	}
	ok, err := c.rdb.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, wrap("set", err)
	}
	return ok, nil
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
