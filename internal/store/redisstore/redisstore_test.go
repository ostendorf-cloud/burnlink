// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package redisstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ostendorf-cloud/burnlink/internal/store"
	"github.com/ostendorf-cloud/burnlink/internal/store/redisstore"
)

// testAddrEnv names the environment variable that holds the host:port of a
// real Redis-compatible server (Valkey, the deployment's store, or Redis).
// The name says REDIS because the protocol and the client are Redis
// compatible, not because the deployment runs Redis. Tests marked
// "real server" need it. CI starts a service container and sets it; a
// developer runs a server and exports it, for example:
//
//	BURNLINK_TEST_REDIS_ADDR=127.0.0.1:6379 go test -race ./internal/store/...
//
// Without it those tests skip, loudly, and never fall back to a fake: a fake
// proves nothing about SET NX or GETDEL.
const testAddrEnv = "BURNLINK_TEST_REDIS_ADDR"

// realServer returns a client for the real server, or skips with a message
// that names what is missing. It waits up to 30 seconds for the server to
// answer, since a service container may still be starting.
func realServer(t *testing.T) (*redisstore.Client, *store.Secrets, string) {
	t.Helper()

	addr := os.Getenv(testAddrEnv)
	if addr == "" {
		t.Skipf("SKIPPED, NOT VERIFIED: %s is not set, so there is no real Redis-compatible server to test "+
			"SET NX PX, GETDEL and expiry against. Start one and set %s=host:port.", testAddrEnv, testAddrEnv)
	}
	c, err := redisstore.New(redisstore.Options{Addr: addr})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		err := c.Ping(ctx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s=%s is set but the server does not answer: %v", testAddrEnv, addr, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return c, store.NewSecrets(c), addr
}

// uniqueID is a fresh key per test, so tests never see each other's data and
// need no flush of a shared server.
func uniqueID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return "burnlink-test-" + hex.EncodeToString(b)
}

func TestRealServerPutRefusesOverwrite(t *testing.T) {
	t.Parallel()
	_, s, _ := realServer(t)
	ctx := t.Context()
	id := uniqueID(t)

	if err := s.Put(ctx, id, []byte("first"), time.Minute); err != nil {
		t.Fatalf("first Put() error = %v", err)
	}
	if err := s.Put(ctx, id, []byte("second"), time.Minute); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second Put() error = %v, want ErrExists", err)
	}
	got, err := s.Take(ctx, id)
	if err != nil || !bytes.Equal(got, []byte("first")) {
		t.Errorf("Take() = %q, %v, want the first value", got, err)
	}
}

// TestRealServerConcurrentPutOnlyOneWins proves the NX is enforced by the
// store, not by a read followed by a write.
func TestRealServerConcurrentPutOnlyOneWins(t *testing.T) {
	t.Parallel()
	_, s, _ := realServer(t)

	const writers = 32
	for round := range 20 {
		id := uniqueID(t)
		var wins, exists atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				switch err := s.Put(t.Context(), id, []byte{byte(w)}, time.Minute); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, store.ErrExists):
					exists.Add(1)
				default:
					t.Errorf("Put() error = %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || exists.Load() != writers-1 {
			t.Fatalf("round %d: wins = %d, exists = %d, want 1 and %d", round, wins.Load(), exists.Load(), writers-1)
		}
	}
}

func TestRealServerTake(t *testing.T) {
	t.Parallel()
	_, s, _ := realServer(t)
	ctx := t.Context()

	// Every byte value, so nothing is mangled as text.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}

	cases := []struct {
		name  string
		value []byte
	}{
		{"text", []byte("ciphertext")},
		{"every byte value", all},
		{"empty", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := uniqueID(t)
			if err := s.Put(ctx, id, tc.value, time.Minute); err != nil {
				t.Fatalf("Put() error = %v", err)
			}
			got, err := s.Take(ctx, id)
			if err != nil || !bytes.Equal(got, tc.value) {
				t.Fatalf("Take() = %q, %v, want %q", got, err, tc.value)
			}
			if _, err := s.Take(ctx, id); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("second Take() error = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestRealServerConcurrentTakeServesOneReader is the proof that a reveal and
// a delete are one operation: of two readers racing for the same secret,
// exactly one is served. It repeats the race many times, since a GET then DEL
// implementation loses it only sometimes.
func TestRealServerConcurrentTakeServesOneReader(t *testing.T) {
	t.Parallel()
	_, s, _ := realServer(t)

	for _, readers := range []int{2, 16} {
		for round := range 300 {
			id := uniqueID(t)
			if err := s.Put(t.Context(), id, []byte("secret"), time.Minute); err != nil {
				t.Fatalf("Put() error = %v", err)
			}
			var served, refused atomic.Int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for range readers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					switch got, err := s.Take(t.Context(), id); {
					case err == nil && string(got) == "secret":
						served.Add(1)
					case errors.Is(err, store.ErrNotFound):
						refused.Add(1)
					default:
						t.Errorf("Take() = %q, %v", got, err)
					}
				}()
			}
			close(start)
			wg.Wait()
			if served.Load() != 1 || refused.Load() != int32(readers-1) {
				t.Fatalf("%d readers, round %d: served = %d, refused = %d, want 1 and %d",
					readers, round, served.Load(), refused.Load(), readers-1)
			}
		}
	}
}

// TestRealServerSecretExpiresOnItsOwn proves the lifetime is the server's:
// the key carries a TTL no longer than asked for, and it disappears with no
// call from this service.
func TestRealServerSecretExpiresOnItsOwn(t *testing.T) {
	t.Parallel()
	_, s, addr := realServer(t)
	ctx := t.Context()
	id := uniqueID(t)

	if err := s.Put(ctx, id, []byte("secret"), 500*time.Millisecond); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	raw := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = raw.Close() })
	ttl, err := raw.PTTL(ctx, store.SecretKeyPrefix+id).Result()
	if err != nil {
		t.Fatalf("PTTL error = %v", err)
	}
	if ttl <= 0 || ttl > 500*time.Millisecond {
		t.Errorf("PTTL = %v, want within (0, 500ms]", ttl)
	}

	time.Sleep(900 * time.Millisecond)
	if _, err := s.Take(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Take() after expiry error = %v, want ErrNotFound", err)
	}
	// An expired id can be written again.
	if err := s.Put(ctx, id, []byte("again"), time.Minute); err != nil {
		t.Errorf("Put() after expiry error = %v, want nil", err)
	}
}

// TestRealServerGetDoesNotConsume covers store.Store's plain Get.
func TestRealServerGetDoesNotConsume(t *testing.T) {
	t.Parallel()
	c, s, _ := realServer(t)
	ctx := t.Context()
	id := uniqueID(t)

	key := store.SecretKeyPrefix + id
	if _, ok, err := c.Get(ctx, key); ok || err != nil {
		t.Fatalf("Get() of a missing key = %v, %v, want false, nil", ok, err)
	}
	if err := s.Put(ctx, id, []byte("v"), time.Minute); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	for range 2 {
		if got, ok, err := c.Get(ctx, key); !ok || err != nil || string(got) != "v" {
			t.Fatalf("Get() = %q, %v, %v, want v, true, nil", got, ok, err)
		}
	}
}

func TestRealServerPing(t *testing.T) {
	t.Parallel()
	_, s, _ := realServer(t)
	if err := s.Ping(t.Context()); err != nil {
		t.Errorf("Ping() error = %v, want nil", err)
	}
}

// The tests below need no server: they start none and use a closed port.

// closedAddr returns an address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return addr
}

// TestUnreachableStore proves the readiness input is honest: while the store
// cannot be reached every operation errors, and the error is never a
// sentinel that the API would read as "not found" or "exists".
func TestUnreachableStore(t *testing.T) {
	t.Parallel()

	const password = "dummy-password-not-real"
	c, err := redisstore.New(redisstore.Options{Addr: closedAddr(t), Username: "dummy-user", Password: password})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := store.NewSecrets(c)

	ops := map[string]func(ctx context.Context) error{
		"ping": s.Ping,
		"put":  func(ctx context.Context) error { return s.Put(ctx, "id", []byte("v"), time.Minute) },
		"take": func(ctx context.Context) error { _, err := s.Take(ctx, "id"); return err },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := op(ctx)
			if err == nil {
				t.Fatal("error = nil, want an error")
			}
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) {
				t.Errorf("error = %v, must not be a sentinel", err)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("error leaks the password: %q", err)
			}
		})
	}
}

func TestRefusesALifetimeTheStoreCannotHold(t *testing.T) {
	t.Parallel()

	c, err := redisstore.New(redisstore.Options{Addr: closedAddr(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	for _, ttl := range []time.Duration{0, -time.Second, time.Nanosecond, 999 * time.Microsecond} {
		// The address is closed, so a command that reached the wire would
		// fail with a network error; the ttl error comes first.
		_, err := c.SetNX(t.Context(), "id", []byte("v"), ttl)
		if err == nil || !strings.Contains(err.Error(), "ttl") {
			t.Errorf("SetNX(ttl=%v) error = %v, want a ttl error", ttl, err)
		}
	}
}

func TestNewRequiresAnAddress(t *testing.T) {
	t.Parallel()
	if _, err := redisstore.New(redisstore.Options{}); err == nil {
		t.Error("New() error = nil, want an error for an empty address")
	}
}
