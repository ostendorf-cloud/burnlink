// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"encoding/base64"
	"fmt"
)

// The decoders are as strict as the page's: only the alphabet, canonical
// trailing bits, and for the standard alphabet padding to a multiple of four.
// Go's own decoder skips a newline and a carriage return, so the alphabet is
// checked first.

// EncodeBase64URL encodes without padding.
func EncodeBase64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// EncodeBase64 encodes with padding.
func EncodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// DecodeBase64URL decodes unpadded, canonical base64url.
func DecodeBase64URL(s string) ([]byte, error) {
	if !onlyAlphabet(s, true) || len(s)%4 == 1 {
		return nil, fmt.Errorf("%w: not base64url", ErrMalformed)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not canonical base64url", ErrMalformed)
	}
	return b, nil
}

// DecodeBase64 decodes padded, canonical standard base64.
func DecodeBase64(s string) ([]byte, error) {
	if !onlyAlphabet(s, false) || len(s)%4 != 0 {
		return nil, fmt.Errorf("%w: not base64", ErrMalformed)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not canonical base64", ErrMalformed)
	}
	return b, nil
}

func onlyAlphabet(s string, url bool) bool {
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case url && (c == '-' || c == '_'):
		case !url && (c == '+' || c == '/'):
		case !url && c == '=' && i >= len(s)-2:
			pad++
		default:
			return false
		}
		if pad > 0 && c != '=' {
			return false
		}
	}
	return true
}
