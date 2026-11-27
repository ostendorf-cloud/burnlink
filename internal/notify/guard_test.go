// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		addr    string
		blocked bool
	}{
		{name: "public v4", addr: "8.8.8.8"},
		{name: "public v4 cloudflare", addr: "1.1.1.1"},
		{name: "public v6", addr: "2606:4700:4700::1111"},
		{name: "mapped public v4", addr: "::ffff:8.8.8.8"},

		{name: "unspecified v4", addr: "0.0.0.0", blocked: true},
		{name: "this network", addr: "0.1.2.3", blocked: true},
		{name: "private 10", addr: "10.0.0.1", blocked: true},
		{name: "private 172.16 low edge", addr: "172.16.0.0", blocked: true},
		{name: "private 172.31 high edge", addr: "172.31.255.255", blocked: true},
		{name: "just below private 172.16", addr: "172.15.255.255"},
		{name: "just above private 172.31", addr: "172.32.0.0"},
		{name: "private 192.168", addr: "192.168.1.1", blocked: true},
		{name: "loopback", addr: "127.0.0.1", blocked: true},
		{name: "loopback high", addr: "127.255.255.254", blocked: true},
		{name: "link local", addr: "169.254.1.1", blocked: true},
		{name: "cloud metadata", addr: "169.254.169.254", blocked: true},
		{name: "cgnat low edge", addr: "100.64.0.0", blocked: true},
		{name: "cgnat high edge", addr: "100.127.255.255", blocked: true},
		{name: "just below cgnat", addr: "100.63.255.255"},
		{name: "just above cgnat", addr: "100.128.0.0"},
		{name: "ietf protocol assignments", addr: "192.0.0.8", blocked: true},
		{name: "documentation 1", addr: "192.0.2.1", blocked: true},
		{name: "documentation 2", addr: "198.51.100.7", blocked: true},
		{name: "documentation 3", addr: "203.0.113.200", blocked: true},
		{name: "benchmarking low", addr: "198.18.0.1", blocked: true},
		{name: "benchmarking high", addr: "198.19.255.255", blocked: true},
		{name: "6to4 relay anycast", addr: "192.88.99.1", blocked: true},
		{name: "multicast", addr: "224.0.0.1", blocked: true},
		{name: "reserved", addr: "240.0.0.1", blocked: true},
		{name: "broadcast", addr: "255.255.255.255", blocked: true},

		{name: "unspecified v6", addr: "::", blocked: true},
		{name: "loopback v6", addr: "::1", blocked: true},
		{name: "link local v6", addr: "fe80::1", blocked: true},
		{name: "unique local fc00", addr: "fc00::1", blocked: true},
		{name: "unique local fd00", addr: "fd12:3456::1", blocked: true},
		{name: "multicast v6", addr: "ff02::1", blocked: true},
		{name: "documentation v6", addr: "2001:db8::1", blocked: true},
		{name: "documentation v6 3fff", addr: "3fff::1", blocked: true},
		{name: "teredo", addr: "2001:0:4136:e378:8000:63bf:3fff:fdd2", blocked: true},
		{name: "6to4 embedding loopback", addr: "2002:7f00:1::1", blocked: true},
		{name: "nat64 embedding loopback", addr: "64:ff9b::7f00:1", blocked: true},
		{name: "ipv4 compatible", addr: "::7f00:1", blocked: true},
		{name: "mapped loopback", addr: "::ffff:127.0.0.1", blocked: true},
		{name: "mapped private", addr: "::ffff:10.1.2.3", blocked: true},
		{name: "mapped metadata", addr: "::ffff:169.254.169.254", blocked: true},
		{name: "zone", addr: "fe80::1%eth0", blocked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q) error = %v", tc.addr, err)
			}
			err = CheckAddr(addr)
			if tc.blocked && !errors.Is(err, ErrBlocked) {
				t.Errorf("CheckAddr(%s) = %v, want ErrBlocked", tc.addr, err)
			}
			if !tc.blocked && err != nil {
				t.Errorf("CheckAddr(%s) = %v, want nil", tc.addr, err)
			}
		})
	}

	t.Run("invalid address", func(t *testing.T) {
		t.Parallel()
		if err := CheckAddr(netip.Addr{}); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckAddr(zero) = %v, want ErrBlocked", err)
		}
	})
}

func TestGuardControl(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		network string
		address string
		blocked bool
	}{
		{name: "public v4 on 443", network: "tcp4", address: "8.8.8.8:443"},
		{name: "public v6 on 443", network: "tcp6", address: "[2606:4700:4700::1111]:443"},
		{name: "loopback", network: "tcp4", address: "127.0.0.1:443", blocked: true},
		{name: "private", network: "tcp4", address: "10.0.0.5:443", blocked: true},
		{name: "mapped loopback", network: "tcp6", address: "[::ffff:127.0.0.1]:443", blocked: true},
		{name: "public on port 80", network: "tcp4", address: "8.8.8.8:80", blocked: true},
		{name: "public on port 8443", network: "tcp4", address: "8.8.8.8:8443", blocked: true},
		{name: "udp", network: "udp4", address: "8.8.8.8:443", blocked: true},
		{name: "unix", network: "unix", address: "/var/run/docker.sock", blocked: true},
		{name: "no port", network: "tcp4", address: "8.8.8.8", blocked: true},
		{name: "a name instead of an address", network: "tcp4", address: "example.com:443", blocked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := guardControl(tc.network, tc.address, nil)
			if tc.blocked && !errors.Is(err, ErrBlocked) {
				t.Errorf("guardControl(%s, %s) = %v, want ErrBlocked", tc.network, tc.address, err)
			}
			if !tc.blocked && err != nil {
				t.Errorf("guardControl(%s, %s) = %v, want nil", tc.network, tc.address, err)
			}
		})
	}
}

// A name is resolved by the dialer, and the hook sees the address the name
// resolved to. "localhost" resolves through the hosts file, not the network,
// and stands for any name an attacker points at a private address.
func TestDialerRefusesAResolvedPrivateAddress(t *testing.T) {
	t.Parallel()

	d := net.Dialer{Timeout: time.Second, Control: guardControl}
	conn, err := d.DialContext(t.Context(), "tcp", "localhost:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext(localhost:443) connected, want a refusal")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("DialContext(localhost:443) error = %v, want ErrBlocked", err)
	}
}

// The whole client, with the real guarded transport, against a server that
// listens on loopback: the connection must never be made.
func TestNotifierNeverReachesALoopbackServer(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)

	var logs strings.Builder
	n := New(Config{
		Logger: newTestLogger(&logs),
		Sleep:  func(context.Context, time.Duration) error { return nil },
	})
	n.Notify(t.Context(), "id", time.Now(), srv.URL)
	if err := n.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("server received %d requests, want 0", got)
	}
	if !strings.Contains(logs.String(), "destination not allowed") {
		t.Errorf("log = %q, want the destination refusal", logs.String())
	}
	if strings.Contains(logs.String(), srv.URL) || strings.Contains(logs.String(), "127.0.0.1") {
		t.Errorf("log names the destination: %q", logs.String())
	}
}
