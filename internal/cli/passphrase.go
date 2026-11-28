// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxPassphraseFileBytes is far more than a passphrase needs and keeps a
// wrong path, such as a large file, from being read into memory.
const maxPassphraseFileBytes = 64 << 10

// passphrase returns the passphrase the caller set, or "" for none. The order
// is the flag, then BURNLINK_PASSPHRASE_FILE, then BURNLINK_PASSPHRASE. There
// is deliberately no way to pass the value itself as an argument.
//
// A file that is named but empty is an error and not "no passphrase": the
// sender would send a secret without the protection they asked for.
func passphrase(flagPath string, env Env) (string, error) {
	path := flagPath
	if path == "" {
		path = env.Getenv(EnvPassphraseFile)
	}
	if path == "" {
		return env.Getenv(EnvPassphrase), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read passphrase file: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxPassphraseFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read passphrase file: %w", err)
	}
	if len(raw) > maxPassphraseFileBytes {
		return "", errors.New("passphrase file is too large to be a passphrase")
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	clear(raw)
	if text == "" {
		return "", errors.New("passphrase file is empty")
	}
	return text, nil
}
