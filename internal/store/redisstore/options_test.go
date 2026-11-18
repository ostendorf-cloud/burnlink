// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package redisstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// These tests need no server. They pin the client's configuration and the
// bytes it sends, which a behavioural test against a healthy server would
// not notice changing.

func TestBuildOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		opts  Options
		check func(t *testing.T, o *redis.Options)
	}{
		{
			name: "plain",
			opts: Options{Addr: "store:6379", Username: "u", Password: "p"},
			check: func(t *testing.T, o *redis.Options) {
				if o.Addr != "store:6379" || o.Username != "u" || o.Password != "p" {
					t.Errorf("address or credentials not passed through: %q %q %q", o.Addr, o.Username, o.Password)
				}
				if o.TLSConfig != nil {
					t.Errorf("TLSConfig = %v, want nil without TLS", o.TLSConfig)
				}
			},
		},
		{
			name: "tls",
			opts: Options{Addr: "store:6379", TLS: true},
			check: func(t *testing.T, o *redis.Options) {
				c := o.TLSConfig
				if c == nil {
					t.Fatal("TLSConfig = nil, want a TLS config")
				}
				if c.MinVersion != tls.VersionTLS12 {
					t.Errorf("MinVersion = %#x, want TLS 1.2", c.MinVersion)
				}
				if c.ServerName != "" {
					t.Errorf("ServerName = %q, want empty so it is inferred from the address", c.ServerName)
				}
				if c.InsecureSkipVerify { //nolint:gosec // asserting it is off
					t.Error("InsecureSkipVerify = true, want false")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := buildOptions(tc.opts)
			tc.check(t, o)

			// Settings that hold for every configuration.
			if o.MaxRetries != -1 {
				t.Errorf("MaxRetries = %d, want -1 (no retries)", o.MaxRetries)
			}
			if !o.DisableIdentity {
				t.Error("DisableIdentity = false, want true (no CLIENT SETINFO)")
			}
			if o.Protocol != 2 {
				t.Errorf("Protocol = %d, want 2", o.Protocol)
			}
			for name, got := range map[string]time.Duration{
				"DialTimeout": o.DialTimeout, "ReadTimeout": o.ReadTimeout, "WriteTimeout": o.WriteTimeout,
			} {
				if got != 2*time.Second {
					t.Errorf("%s = %v, want 2s", name, got)
				}
			}
			if o.MaintNotificationsConfig == nil || o.MaintNotificationsConfig.Mode != maintnotifications.ModeDisabled {
				t.Errorf("MaintNotificationsConfig = %+v, want mode disabled", o.MaintNotificationsConfig)
			}
		})
	}
}

// recorder is a go-redis hook that notes every command before it is sent.
type recorder struct {
	mu   sync.Mutex
	cmds [][]any
}

func (r *recorder) DialHook(next redis.DialHook) redis.DialHook { return next }

func (r *recorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		r.mu.Lock()
		r.cmds = append(r.cmds, cmd.Args())
		r.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (r *recorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// TestSetNXSendsPXAndNXForEveryTTL builds the real command through a real
// client and reads it before it hits the wire. The address is a closed port,
// so the send itself fails, which does not matter here.
func TestSetNXSendsPXAndNXForEveryTTL(t *testing.T) {
	t.Parallel()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cases := []struct {
		name   string
		ttl    time.Duration
		wantMs int64
	}{
		{"whole second, where go-redis would send EX", 10 * time.Second, 10000},
		{"one second", time.Second, 1000},
		{"minutes", 3 * time.Minute, 180000},
		{"fractional second", 1500 * time.Millisecond, 1500},
		{"one millisecond", time.Millisecond, 1},
		{"sub millisecond remainder is truncated", 2*time.Millisecond + 900*time.Microsecond, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := New(Options{Addr: addr})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(func() { _ = c.Close() })
			rec := &recorder{}
			c.rdb.AddHook(rec)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			_, _ = c.SetNX(ctx, "k", []byte("v"), tc.ttl)

			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.cmds) != 1 {
				t.Fatalf("commands = %v, want exactly one", rec.cmds)
			}
			args := rec.cmds[0]
			want := []any{"set", "k", []byte("v"), "px", tc.wantMs, "nx"}
			if len(args) != len(want) {
				t.Fatalf("args = %v, want %v", args, want)
			}
			for i := range want {
				if b, ok := want[i].([]byte); ok {
					if got, ok := args[i].([]byte); !ok || !bytes.Equal(got, b) {
						t.Errorf("args[%d] = %v, want %v", i, args[i], want[i])
					}
					continue
				}
				if args[i] != want[i] {
					t.Errorf("args[%d] = %v, want %v", i, args[i], want[i])
				}
			}
		})
	}
}

func TestSlogLoggerWritesAtDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slogLogger{l: func() *slog.Logger { return logger }}.Printf(t.Context(), "dial %s failed", "x:1")

	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "dial x:1 failed") {
		t.Errorf("log output = %q, want a debug line with the message", out)
	}

	// At the default info level nothing is written.
	buf.Reset()
	info := slog.New(slog.NewTextHandler(&buf, nil))
	slogLogger{l: func() *slog.Logger { return info }}.Printf(t.Context(), "noise")
	if buf.Len() != 0 {
		t.Errorf("log output = %q, want nothing at info level", buf.String())
	}
}
