// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		raw   string
		valid bool
	}{
		{name: "https url", raw: "https://hooks.example.com/burnlink", valid: true},
		{name: "explicit port 443", raw: "https://hooks.example.com:443/x", valid: true},
		{name: "query string", raw: "https://hooks.example.com/x?token=abc", valid: true},
		{name: "public v4 literal", raw: "https://8.8.8.8/x", valid: true},
		{name: "public v6 literal", raw: "https://[2606:4700:4700::1111]/x", valid: true},
		{name: "upper case scheme", raw: "HTTPS://hooks.example.com/x", valid: true},

		{name: "empty", raw: ""},
		{name: "http", raw: "http://hooks.example.com/x"},
		{name: "ftp", raw: "ftp://hooks.example.com/x"},
		{name: "file", raw: "file:///etc/passwd"},
		{name: "gopher", raw: "gopher://hooks.example.com/x"},
		{name: "no scheme", raw: "hooks.example.com/x"},
		{name: "scheme relative", raw: "//hooks.example.com/x"},
		{name: "opaque", raw: "https:hooks.example.com"},
		{name: "no host", raw: "https:///x"},
		{name: "user info", raw: "https://user:pass@hooks.example.com/x"},
		{name: "user name only", raw: "https://user@hooks.example.com/x"},
		{name: "fragment", raw: "https://hooks.example.com/x#frag"},
		{name: "empty fragment", raw: "https://hooks.example.com/x#"},
		{name: "port 80", raw: "https://hooks.example.com:80/x"},
		{name: "port 8443", raw: "https://hooks.example.com:8443/x"},
		{name: "loopback v4", raw: "https://127.0.0.1/x"},
		{name: "loopback v6", raw: "https://[::1]/x"},
		{name: "private v4", raw: "https://10.0.0.1/x"},
		{name: "metadata address", raw: "https://169.254.169.254/latest/meta-data"},
		{name: "cgnat", raw: "https://100.64.0.1/x"},
		{name: "documentation", raw: "https://192.0.2.1/x"},
		{name: "mapped loopback", raw: "https://[::ffff:127.0.0.1]/x"},
		{name: "unspecified", raw: "https://0.0.0.0/x"},
		{name: "space", raw: "https://hooks.example.com/a b"},
		{name: "control character", raw: "https://hooks.example.com/a\x00b"},
		{name: "newline", raw: "https://hooks.example.com/a\nb"},
		{name: "non ascii host", raw: "https://höoks.example.com/x"},
		{name: "too long", raw: "https://hooks.example.com/" + strings.Repeat("a", MaxTargetBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.raw)
			if tc.valid && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.raw, err)
			}
			if !tc.valid && !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("Validate(%q) = %v, want ErrInvalidTarget", tc.raw, err)
			}
		})
	}
}

func TestValidateErrorNamesNoPartOfTheURL(t *testing.T) {
	t.Parallel()

	err := Validate("https://user:s3cr3t-token@hooks.example.com/x")
	if err == nil {
		t.Fatal("Validate() = nil, want an error")
	}
	for _, part := range []string{"s3cr3t-token", "hooks.example.com", "user"} {
		if strings.Contains(err.Error(), part) {
			t.Errorf("error %q names %q", err, part)
		}
	}
}
