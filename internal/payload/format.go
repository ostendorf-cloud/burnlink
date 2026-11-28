// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package payload is the Go side of the burnlink payload format. The page's
// web/src/lib/crypto.ts is the other side. Both read their constants from
// format.json, and the vectors in testdata/format keep the two honest on the
// bytes. See docs/adr/0002-the-payload-format-stays-from-old-burnlink.md.
//
// Layout, all binary:
//
//	version (1 byte) | flags (1 byte) | salt (only with a passphrase) |
//	iv | AES-256-GCM ciphertext with its tag
//
// The header, everything before the ciphertext, is the GCM additional data.
package payload

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

//go:embed format.json
var formatJSON []byte

// Why a payload could not be opened. Callers compare with errors.Is.
var (
	ErrMalformed          = errors.New("payload is malformed")
	ErrUnsupported        = errors.New("payload version or flags are not supported")
	ErrPassphraseRequired = errors.New("a passphrase is required")
	ErrFailed             = errors.New("decryption failed")
)

// spec mirrors format.json.
type spec struct {
	Version int `json:"version"`
	Flags   struct {
		Passphrase int `json:"passphrase"`
	} `json:"flags"`
	KeyBytes  int `json:"keyBytes"`
	IVBytes   int `json:"ivBytes"`
	SaltBytes int `json:"saltBytes"`
	TagBytes  int `json:"tagBytes"`
	PadBlock  int `json:"padBlock"`
	PBKDF2    struct {
		Hash       string `json:"hash"`
		Iterations int    `json:"iterations"`
	} `json:"pbkdf2"`
	HKDF struct {
		Hash string `json:"hash"`
		Info string `json:"info"`
	} `json:"hkdf"`
}

// Codec encrypts and decrypts payloads of the format in format.json.
type Codec struct {
	spec spec
	// rand is the source of salts and IVs. Only tests replace it.
	rand io.Reader
}

// New reads format.json and checks it describes something this package can
// implement. The page accepts any value in the file, this side does not: a
// hash other than SHA-256, or a tag or IV size other than the ones AES-GCM
// uses here, is a format change that needs code.
func New() (*Codec, error) {
	var s spec
	dec := json.NewDecoder(bytes.NewReader(formatJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("read payload format: %w", err)
	}
	switch {
	case s.Version < 1 || s.Version > 255:
		return nil, errors.New("payload format: version must fit one byte")
	case s.Flags.Passphrase < 1 || s.Flags.Passphrase > 255 || s.Flags.Passphrase&(s.Flags.Passphrase-1) != 0:
		return nil, errors.New("payload format: the passphrase flag must be one bit")
	case s.KeyBytes != 32:
		return nil, errors.New("payload format: key must be 32 bytes")
	case s.IVBytes != 12 || s.TagBytes != 16:
		return nil, errors.New("payload format: iv and tag must be 12 and 16 bytes")
	case s.SaltBytes < 1:
		return nil, errors.New("payload format: salt must not be empty")
	case s.PadBlock < 1:
		return nil, errors.New("payload format: pad block must be positive")
	case s.PBKDF2.Hash != "SHA-256" || s.HKDF.Hash != "SHA-256":
		return nil, errors.New("payload format: only SHA-256 is implemented")
	case s.PBKDF2.Iterations < 1:
		return nil, errors.New("payload format: pbkdf2 iterations must be positive")
	case s.HKDF.Info == "":
		return nil, errors.New("payload format: hkdf info must not be empty")
	}
	return &Codec{spec: s, rand: rand.Reader}, nil
}

// KeyBytes is the size of a link key.
func (c *Codec) KeyBytes() int { return c.spec.KeyBytes }

// GenerateKey returns a fresh link key.
func (c *Codec) GenerateKey() ([]byte, error) {
	key := make([]byte, c.spec.KeyBytes)
	if _, err := io.ReadFull(c.rand, key); err != nil {
		return nil, fmt.Errorf("generate link key: %w", err)
	}
	return key, nil
}
