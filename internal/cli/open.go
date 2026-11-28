// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/ostendorf-cloud/burnlink/internal/client"
	"github.com/ostendorf-cloud/burnlink/internal/payload"
)

// maxLinkBytes bounds a link read from standard input.
const maxLinkBytes = 8 << 10

// gone is said whenever opening failed after the server answered: it deleted
// the secret in the same step, so the person has to ask for a new one.
const gone = "the server has already deleted the secret, it cannot be opened again"

// open opens a link and delivers the content. Text goes to standard output,
// a file is saved. Options come before the link.
func open(ctx context.Context, args []string, env Env) error {
	flags := newFlagSet("open", "[options] LINK", env)
	out := flags.String("out", "", "write the content to this `path`, which must not exist, or into this directory; - writes it to standard output (default: text to standard output, a file into the current directory)")
	passFile := flags.String("passphrase-file", "", "read the passphrase from this `path` (see $"+EnvPassphrase+" and $"+EnvPassphraseFile+")")
	if err := parse(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return &usageError{msg: "open takes one link, or - to read it from standard input"}
	}
	raw := flags.Arg(0)
	if raw == "-" {
		line, err := bufio.NewReader(io.LimitReader(env.Stdin, maxLinkBytes)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read the link: %w", err)
		}
		raw = line
	}
	// Parsed before anything is asked of the server: a mangled link must not
	// spend the secret.
	codec, err := payload.New()
	if err != nil {
		return err
	}
	link, err := client.ParseLink(raw, codec.KeyBytes())
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	defer clear(link.Key)
	pass, err := passphrase(*passFile, env)
	if err != nil {
		return err
	}
	api, err := client.New(link.Origin, httpClient(env))
	if err != nil {
		return &usageError{msg: err.Error()}
	}

	// The destination is checked before the secret is spent, so an existing
	// file can not cost the content.
	dest, err := prepareDestination(*out)
	if err != nil {
		return err
	}
	delivered := false
	defer func() {
		if !delivered {
			dest.discard()
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	sealed, err := api.Open(ctx, link.ID)
	if err != nil {
		if errors.Is(err, client.ErrNotAvailable) {
			return errors.New("the secret is not available: it was opened before, has expired, or never existed")
		}
		return fmt.Errorf("open the secret: %w", err)
	}
	content, err := codec.Decrypt(sealed, link.Key, pass)
	if err != nil {
		return decryptFailure(err)
	}
	defer clear(content.Data)
	if err := deliver(content, dest, env); err != nil {
		return err
	}
	delivered = true
	return nil
}

func decryptFailure(err error) error {
	switch {
	case errors.Is(err, payload.ErrPassphraseRequired):
		return errors.New("the secret needs a passphrase and " + gone +
			", ask for a new link and set " + EnvPassphrase + " or " + EnvPassphraseFile + " before opening it")
	case errors.Is(err, payload.ErrFailed):
		return errors.New("decryption failed, the passphrase or the link key is wrong or the data was changed, and " + gone)
	case errors.Is(err, payload.ErrUnsupported):
		return errors.New("this version of burnlink-cli does not understand the secret's format and " + gone)
	default:
		return errors.New("the secret is not in a format this client understands and " + gone)
	}
}

// destination is where open puts the content, decided before the secret is
// spent.
type destination struct {
	// stdout sends the content to standard output.
	stdout bool
	// file is a path that was created up front, empty if not.
	file *os.File
	path string
	// dir is a directory that receives a file under a name of the sender's
	// choosing, made safe.
	dir string
}

func prepareDestination(out string) (destination, error) {
	if out == "-" {
		return destination{stdout: true}, nil
	}
	if out == "" {
		return destination{}, nil
	}
	info, err := os.Stat(out)
	switch {
	case err == nil && info.IsDir():
		return destination{dir: out}, nil
	case err == nil:
		return destination{}, fmt.Errorf("%s exists, open does not replace a file", out)
	case !errors.Is(err, fs.ErrNotExist):
		return destination{}, fmt.Errorf("check the destination: %w", err)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return destination{}, fmt.Errorf("create the destination: %w", err)
	}
	return destination{file: f, path: out}, nil
}

// discard removes a file that was created up front and never filled.
func (d destination) discard() {
	if d.file != nil {
		_ = d.file.Close()
		_ = os.Remove(d.path)
	}
}

func deliver(content payload.Content, dest destination, env Env) error {
	data, name := []byte(content.Text), "secret.txt"
	if content.Kind == payload.KindFile {
		data, name = content.Data, safeName(content.Name)
	}

	switch {
	case dest.file != nil:
		return writeAndClose(dest.file, dest.path, data, env)
	case dest.stdout || (dest.dir == "" && content.Kind == payload.KindText):
		if env.StdoutIsTerminal {
			shown, changed := escapeForTerminal(string(data))
			if changed {
				_, _ = fmt.Fprintln(env.Stderr, "Control characters in the secret are shown as escapes. Redirect the output or use --out to get the exact bytes.")
			}
			data = []byte(shown)
		}
		if _, err := env.Stdout.Write(data); err != nil {
			return fmt.Errorf("write the secret: %w", err)
		}
		return nil
	}
	dir := firstNonEmpty(dest.dir, env.WorkDir, ".")
	f, path, err := createUnique(dir, name)
	if err != nil {
		return err
	}
	return writeAndClose(f, path, data, env)
}

func writeAndClose(f *os.File, path string, data []byte, env Env) error {
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(env.Stderr, "Saved %d bytes to %s\n", len(data), strings.ToValidUTF8(path, "?"))
	return nil
}
