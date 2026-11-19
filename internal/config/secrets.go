// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"time"

	"github.com/ostendorf-cloud/govue/envconf"
)

// Defaults and bounds for the secret API's own limits. None of the values is
// secret shaped, so none has a _FILE twin.
const (
	defaultSecretMaxBytes = 1 << 20 // 1 MiB
	// hardSecretMaxBytes caps SECRET_MAX_BYTES so the size arithmetic in the
	// API layer cannot overflow and one request cannot hold the whole
	// memory limit of a pod.
	hardSecretMaxBytes = 64 << 20

	defaultLifetimeMin     = time.Minute
	defaultLifetimeMax     = 7 * 24 * time.Hour
	defaultLifetimeDefault = 24 * time.Hour
	// hardLifetimeMax is the longest lifetime an operator may allow.
	hardLifetimeMax = 30 * 24 * time.Hour

	defaultRateLimitBurst = 10
	defaultRateLimitPer   = time.Minute
)

// Secrets is what the secret API enforces on every stored secret.
type Secrets struct {
	// MaxBytes is the largest ciphertext accepted, in bytes, from
	// SECRET_MAX_BYTES.
	MaxBytes int
	// LifetimeMin, LifetimeMax and LifetimeDefault bound the lifetime a
	// sender may ask for and name the one used when none is asked for. They
	// come from SECRET_LIFETIME_MIN, SECRET_LIFETIME_MAX and
	// SECRET_LIFETIME_DEFAULT, whole seconds or more.
	LifetimeMin     time.Duration
	LifetimeMax     time.Duration
	LifetimeDefault time.Duration
}

// RateLimit is the per client address budget of the secret endpoints: Burst
// requests at once, refilled completely every Per.
type RateLimit struct {
	// Burst is from RATE_LIMIT_BURST.
	Burst int
	// Per is from RATE_LIMIT_PER.
	Per time.Duration
}

// loadSecrets reads the secret limits and the rate limit and returns the
// problems it found appended to problems.
func loadSecrets(l *envconf.Loader, problems []error) (Secrets, RateLimit, []error) {
	s := Secrets{
		MaxBytes:        l.Int("SECRET_MAX_BYTES", defaultSecretMaxBytes, 1, hardSecretMaxBytes),
		LifetimeMin:     l.Duration("SECRET_LIFETIME_MIN", defaultLifetimeMin, time.Second, hardLifetimeMax),
		LifetimeMax:     l.Duration("SECRET_LIFETIME_MAX", defaultLifetimeMax, time.Second, hardLifetimeMax),
		LifetimeDefault: l.Duration("SECRET_LIFETIME_DEFAULT", defaultLifetimeDefault, time.Second, hardLifetimeMax),
	}
	rl := RateLimit{
		Burst: l.Int("RATE_LIMIT_BURST", defaultRateLimitBurst, 1, 100_000),
		Per:   l.Duration("RATE_LIMIT_PER", defaultRateLimitPer, time.Second, 24*time.Hour),
	}

	// The cross field rules only make sense when every single value parsed;
	// otherwise a typo would also report a misleading ordering problem.
	if l.Err() == nil {
		// The API compares and reports lifetimes in whole seconds, so a
		// fraction would let a lifetime through that is below the minimum.
		for _, d := range []struct {
			name  string
			value time.Duration
		}{
			{"SECRET_LIFETIME_MIN", s.LifetimeMin},
			{"SECRET_LIFETIME_MAX", s.LifetimeMax},
			{"SECRET_LIFETIME_DEFAULT", s.LifetimeDefault},
		} {
			if d.value%time.Second != 0 {
				problems = append(problems, fmt.Errorf("%s (%s) must be a whole number of seconds", d.name, d.value))
			}
		}
		switch {
		case s.LifetimeMin > s.LifetimeMax:
			problems = append(problems, fmt.Errorf(
				"SECRET_LIFETIME_MIN (%s) must not exceed SECRET_LIFETIME_MAX (%s)", s.LifetimeMin, s.LifetimeMax))
		case s.LifetimeDefault < s.LifetimeMin || s.LifetimeDefault > s.LifetimeMax:
			problems = append(problems, fmt.Errorf(
				"SECRET_LIFETIME_DEFAULT (%s) must lie between SECRET_LIFETIME_MIN (%s) and SECRET_LIFETIME_MAX (%s)",
				s.LifetimeDefault, s.LifetimeMin, s.LifetimeMax))
		}
	}
	return s, rl, problems
}
