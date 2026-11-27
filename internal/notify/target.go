// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
)

// MaxTargetBytes is the longest webhook URL accepted.
const MaxTargetBytes = 2048

// ErrInvalidTarget is returned by Validate for a URL that is not an
// acceptable webhook destination. The error carries no part of the URL: a
// URL can hold a token, and the error can reach a log.
var ErrInvalidTarget = errors.New("notify: invalid webhook url")

// Validate checks a sender supplied webhook URL before it is stored. It is
// the early, cheap half of the guard: it can refuse a URL that is wrong on
// its face, and so gives the sender an answer at once. It cannot know what a
// host name resolves to, and a name can change its answer. The connect time
// check in Notifier is the one that decides; passing Validate promises
// nothing about delivery.
//
// A URL passes when it is at most MaxTargetBytes of printable ASCII, uses
// https, names a host, carries no user information and no fragment, uses no
// port or port 443, and does not name an address literal that CheckAddr
// refuses.
func Validate(raw string) error {
	if raw == "" || len(raw) > MaxTargetBytes {
		return ErrInvalidTarget
	}
	for i := range len(raw) {
		// A "#" is refused even when the fragment after it is empty.
		if raw[i] <= 0x20 || raw[i] >= 0x7f || raw[i] == '#' {
			return ErrInvalidTarget
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ErrInvalidTarget
	}
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" {
		return ErrInvalidTarget
	}
	if p := u.Port(); p != "" && p != strconv.Itoa(allowedPort) {
		return ErrInvalidTarget
	}
	host := u.Hostname()
	if host == "" {
		return ErrInvalidTarget
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if CheckAddr(addr) != nil {
			return ErrInvalidTarget
		}
	}
	return nil
}
