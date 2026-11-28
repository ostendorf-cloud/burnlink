// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// header is a payload split up without decrypting it.
type header struct {
	hasPassphrase bool
	salt          []byte
	iv            []byte
	header        []byte
	ciphertext    []byte
}

func (c *Codec) parseHeader(p []byte) (header, error) {
	if len(p) < 2 {
		return header{}, fmt.Errorf("%w: payload too short", ErrMalformed)
	}
	if int(p[0]) != c.spec.Version {
		return header{}, fmt.Errorf("%w: unknown payload version", ErrUnsupported)
	}
	flags := int(p[1])
	if flags&^c.spec.Flags.Passphrase != 0 {
		return header{}, fmt.Errorf("%w: unknown flags", ErrUnsupported)
	}
	h := header{hasPassphrase: flags&c.spec.Flags.Passphrase != 0}
	length := 2 + c.spec.IVBytes
	if h.hasPassphrase {
		length += c.spec.SaltBytes
	}
	if len(p) < length+c.spec.TagBytes {
		return header{}, fmt.Errorf("%w: payload too short", ErrMalformed)
	}
	if h.hasPassphrase {
		h.salt = p[2 : 2+c.spec.SaltBytes]
	}
	h.iv = p[length-c.spec.IVBytes : length]
	h.header = p[:length]
	h.ciphertext = p[length:]
	return h, nil
}

// NeedsPassphrase tells from the header alone whether p wants a passphrase.
func (c *Codec) NeedsPassphrase(p []byte) (bool, error) {
	h, err := c.parseHeader(p)
	if err != nil {
		return false, err
	}
	return h.hasPassphrase, nil
}

// deriveKey runs HKDF over the link key and, with a passphrase, over the link
// key followed by the PBKDF2 output, so both are needed.
func (c *Codec) deriveKey(linkKey []byte, passphrase string, salt []byte) (cipher.AEAD, error) {
	if len(linkKey) != c.spec.KeyBytes {
		return nil, fmt.Errorf("%w: link key must be %d bytes", ErrMalformed, c.spec.KeyBytes)
	}
	ikm := slices.Clone(linkKey)
	// A closure, because append below may move ikm to a new buffer.
	defer func() { clear(ikm) }()
	if salt != nil {
		if !utf8.ValidString(passphrase) {
			return nil, fmt.Errorf("%w: passphrase is not valid UTF-8", ErrMalformed)
		}
		stretched, err := pbkdf2.Key(sha256.New, norm.NFC.String(passphrase), salt, c.spec.PBKDF2.Iterations, 32)
		if err != nil {
			return nil, fmt.Errorf("stretch passphrase: %w", err)
		}
		ikm = append(ikm, stretched...)
		clear(stretched)
	}
	key, err := hkdf.Key(sha256.New, ikm, salt, c.spec.HKDF.Info, 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead, nil
}

// Encrypt returns the payload for content under linkKey, and under the
// passphrase when it is not empty.
func (c *Codec) Encrypt(content Content, linkKey []byte, passphrase string) ([]byte, error) {
	hasPassphrase := passphrase != ""
	var salt []byte
	if hasPassphrase {
		salt = make([]byte, c.spec.SaltBytes)
		if _, err := io.ReadFull(c.rand, salt); err != nil {
			return nil, fmt.Errorf("read salt: %w", err)
		}
	}
	iv := make([]byte, c.spec.IVBytes)
	if _, err := io.ReadFull(c.rand, iv); err != nil {
		return nil, fmt.Errorf("read iv: %w", err)
	}
	head := []byte{byte(c.spec.Version), 0}
	if hasPassphrase {
		head[1] = byte(c.spec.Flags.Passphrase)
	}
	head = append(head, salt...)
	head = append(head, iv...)

	aead, err := c.deriveKey(linkKey, passphrase, salt)
	if err != nil {
		return nil, err
	}
	plain, err := c.encodeContent(content)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return aead.Seal(slices.Clone(head), iv, plain, head), nil
}

// Decrypt returns the content of p. A failure wraps one of ErrMalformed,
// ErrUnsupported, ErrPassphraseRequired or ErrFailed.
func (c *Codec) Decrypt(p, linkKey []byte, passphrase string) (Content, error) {
	h, err := c.parseHeader(p)
	if err != nil {
		return Content{}, err
	}
	if h.hasPassphrase && passphrase == "" {
		return Content{}, ErrPassphraseRequired
	}
	aead, err := c.deriveKey(linkKey, passphrase, h.salt)
	if err != nil {
		return Content{}, err
	}
	plain, err := aead.Open(nil, h.iv, h.ciphertext, h.header)
	if err != nil {
		return Content{}, ErrFailed
	}
	defer clear(plain)
	return decodeContent(plain)
}
