// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/ostendorf-cloud/govue/envconf"
)

// Store is how to reach the Redis-compatible store. The deployment runs
// Valkey, but nothing here is specific to it.
//
// Username and Password are credentials. Each one comes from its own
// variable or from the file named by the variable with a _FILE suffix,
// never both, through envconf.Loader.SecretOrFile. Neither value ever
// appears in an error or in String.
type Store struct {
	// Addr is host:port, from STORE_ADDR. It is required.
	Addr string
	// Username is the ACL user, from STORE_USERNAME or STORE_USERNAME_FILE.
	// Empty means the store's default user.
	Username string
	// Password is from STORE_PASSWORD or STORE_PASSWORD_FILE. Empty means no
	// authentication.
	Password string
	// TLS turns on TLS for the connection, from STORE_TLS. It defaults to
	// false: the in-cluster store is reached over a plain connection.
	TLS bool
}

// String describes the store without any credential, so a logged or printed
// Config never leaks one.
func (s Store) String() string {
	return fmt.Sprintf("store{addr=%s username_set=%t password_set=%t tls=%t}",
		s.Addr, s.Username != "", s.Password != "", s.TLS)
}

// GoString keeps %#v from printing the credentials either.
func (s Store) GoString() string { return s.String() }

// loadStore reads the store's own variables and returns the problems it
// found appended to problems, so Load reports every mistake at once.
func loadStore(l *envconf.Loader, problems []error) (Store, []error) {
	s := Store{
		Addr:     l.Required("STORE_ADDR"),
		Username: l.SecretOrFile("STORE_USERNAME"),
		Password: l.SecretOrFile("STORE_PASSWORD"),
		TLS:      l.Bool("STORE_TLS", false),
	}
	if s.Addr != "" {
		if err := validateAddr(s.Addr); err != nil {
			problems = append(problems, fmt.Errorf("STORE_ADDR: %w", err))
		}
	}
	return s, problems
}

// validateAddr checks host:port without echoing the value: an operator who
// pastes a URL with credentials into the address would otherwise see the
// password again in the error and in the logs.
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return errors.New("must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("port must be a number between 1 and 65535")
	}
	return nil
}
