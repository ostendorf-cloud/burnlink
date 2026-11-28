// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ostendorf-cloud/burnlink/internal/client"
	"github.com/ostendorf-cloud/burnlink/internal/payload"
)

const defaultMime = "application/octet-stream"

// send reads a secret, seals it and prints the link. Nothing but the link goes
// to standard output.
func send(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("send", "[options]", env)
	server := fs.String("server", "", "server `URL` (default $"+EnvServer+" or "+DefaultServer+")")
	lifetime := fs.String("lifetime", "", "how long the link stays valid, such as 30m, 12h or 7d (default: the server's choice)")
	file := fs.String("file", "", "send this `path` as a file instead of reading text from standard input")
	name := fs.String("name", "", "file name shown to the receiver (default: the name of --file)")
	mimeType := fs.String("mime", "", "media type of the file (default: from the extension)")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this `path` (see $"+EnvPassphrase+" and $"+EnvPassphraseFile+")")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return &usageError{msg: "send takes no arguments, the secret comes from standard input or --file"}
	}
	var wantLifetime time.Duration
	if *lifetime != "" {
		d, err := parseLifetime(*lifetime)
		if err != nil {
			return &usageError{msg: err.Error()}
		}
		wantLifetime = d
	}
	if *file == "" && (*name != "" || *mimeType != "") {
		return &usageError{msg: "--name and --mime only apply with --file"}
	}

	origin := firstNonEmpty(*server, env.Getenv(EnvServer), DefaultServer)
	api, err := client.New(origin, httpClient(env))
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	pass, err := passphrase(*passFile, env)
	if err != nil {
		return err
	}
	codec, err := payload.New()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	// The limits come first, so a secret that cannot be stored is refused
	// before it is read, encrypted or sent.
	cfg, err := api.Config(ctx)
	if err != nil {
		return fmt.Errorf("read the server's limits: %w", err)
	}
	if wantLifetime != 0 && (wantLifetime < cfg.LifetimeMin || wantLifetime > cfg.LifetimeMax) {
		return fmt.Errorf("this server keeps a link between %s and %s, not %s", cfg.LifetimeMin, cfg.LifetimeMax, wantLifetime)
	}

	var content payload.Content
	if *file != "" {
		content, err = readFile(*file, *name, *mimeType, cfg.MaxCiphertextBytes)
	} else {
		content, err = readText(env, cfg.MaxCiphertextBytes)
	}
	if err != nil {
		return err
	}
	defer clear(content.Data)

	key, err := codec.GenerateKey()
	if err != nil {
		return err
	}
	defer clear(key)
	sealed, err := codec.Encrypt(content, key, pass)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if len(sealed) > cfg.MaxCiphertextBytes {
		return fmt.Errorf("the encrypted secret is %d bytes, this server accepts at most %d", len(sealed), cfg.MaxCiphertextBytes)
	}
	stored, err := api.Store(ctx, sealed, wantLifetime)
	if err != nil {
		return fmt.Errorf("store the secret: %w", err)
	}
	if _, err := fmt.Fprintln(env.Stdout, api.Link(stored.ID, key)); err != nil {
		return fmt.Errorf("write the link: %w", err)
	}
	if pass != "" {
		_, _ = fmt.Fprintln(env.Stderr, "The link needs the passphrase. Share the two on different channels.")
	}
	_, _ = fmt.Fprintf(env.Stderr, "The link works once and expires at %s.\n", stored.ExpiresAt.UTC().Format(time.RFC3339))
	return nil
}

func readText(env Env, limit int) (payload.Content, error) {
	if env.StdinIsTerminal {
		_, _ = fmt.Fprintln(env.Stderr, "Reading the secret from the terminal. End it with Ctrl-D.")
	}
	raw, err := readLimited(env.Stdin, limit)
	if err != nil {
		return payload.Content{}, err
	}
	defer clear(raw)
	if len(raw) == 0 {
		return payload.Content{}, errors.New("nothing to send: standard input is empty")
	}
	if !utf8.Valid(raw) {
		return payload.Content{}, errors.New("standard input is not UTF-8 text, send binary data with --file")
	}
	return payload.Content{Kind: payload.KindText, Text: string(raw)}, nil
}

func readFile(path, name, mimeType string, limit int) (payload.Content, error) {
	info, err := os.Stat(path)
	if err != nil {
		return payload.Content{}, fmt.Errorf("read the file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return payload.Content{}, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return payload.Content{}, fmt.Errorf("read the file: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := readLimited(f, limit)
	if err != nil {
		return payload.Content{}, err
	}
	if len(raw) == 0 {
		return payload.Content{}, errors.New("nothing to send: the file is empty")
	}
	if name == "" {
		name = filepath.Base(path)
	}
	if mimeType == "" {
		mimeType = mimeFromExtension(path)
	}
	return payload.Content{Kind: payload.KindFile, Name: name, Mime: mimeType, Data: raw}, nil
}

// readLimited reads at most limit bytes and fails on more. The encrypted
// secret is larger than its content, so a smaller secret can still be refused
// later, by the exact check against the server's limit.
func readLimited(r io.Reader, limit int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read the secret: %w", err)
	}
	if len(raw) > limit {
		clear(raw)
		return nil, fmt.Errorf("the secret is larger than the %d bytes this server accepts", limit)
	}
	return raw, nil
}

func mimeFromExtension(path string) string {
	if byExt := mime.TypeByExtension(strings.ToLower(filepath.Ext(path))); byExt != "" {
		if mediaType, _, err := mime.ParseMediaType(byExt); err == nil {
			return mediaType
		}
	}
	return defaultMime
}

// parseLifetime reads a duration and, unlike time.ParseDuration, a count of
// days such as 7d.
func parseLifetime(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseUint(days, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("--lifetime %q is not a duration such as 30m, 12h or 7d", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("--lifetime %q is not a duration such as 30m, 12h or 7d", s)
		}
		d = parsed
	}
	if d < time.Second || d%time.Second != 0 {
		return 0, fmt.Errorf("--lifetime %q must be a whole number of seconds, at least one", s)
	}
	return d, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
