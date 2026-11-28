// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package cli is the burnlink command line: send a secret from a terminal and
// open one, with the same payload format as the page. cmd/burnlink-cli only
// wires the process around it.
//
// Rules the commands keep:
//   - A secret, a passphrase and a link key never appear in an argument, a
//     log line or an error. The passphrase comes from the environment or a
//     file, never from a flag.
//   - Standard output carries only the result: the link of send, the content
//     of open.
//   - Everything from the other side, the content, the file name and the
//     server's own words, is data and is treated as such.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ostendorf-cloud/burnlink/internal/buildinfo"
)

// DefaultServer is where send goes without --server or BURNLINK_SERVER.
const DefaultServer = "https://burnlink.de"

// Environment variables the commands read.
const (
	EnvServer         = "BURNLINK_SERVER"
	EnvPassphrase     = "BURNLINK_PASSPHRASE"
	EnvPassphraseFile = "BURNLINK_PASSPHRASE_FILE"
)

// operationTimeout bounds one command, including the transfer of a file.
const operationTimeout = 5 * time.Minute

// Env is everything a command takes from the process around it.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// HTTP is the client for the server. Nil means a default one.
	HTTP *http.Client
	// StdinIsTerminal and StdoutIsTerminal tell whether a person is typing
	// or reading. They only change hints and escaping, never the result.
	StdinIsTerminal  bool
	StdoutIsTerminal bool
	// WorkDir is where open saves a file when --out names none. Empty means
	// the current directory.
	WorkDir string
}

// errUsage marks a failure whose message the flag package already printed.
var errUsage = errors.New("usage")

// usageError is a wrong call, answered with the exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Run executes one command line and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if len(args) == 0 {
		writeUsage(env.Stderr)
		return exitUsage
	}
	var err error
	switch args[0] {
	case "send":
		err = send(ctx, args[1:], env)
	case "open":
		err = open(ctx, args[1:], env)
	case "version", "--version", "-version":
		info := buildinfo.Read()
		_, _ = fmt.Fprintf(env.Stdout, "burnlink-cli %s (%s)\n", info.Version, info.Commit)
	case "help", "--help", "-h", "-help":
		writeUsage(env.Stdout)
	default:
		err = &usageError{msg: fmt.Sprintf("unknown command %q, see burnlink-cli help", args[0])}
	}
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errUsage):
		return exitUsage
	}
	_, _ = fmt.Fprintln(env.Stderr, "burnlink-cli:", err)
	var usage *usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitFailure
}

func writeUsage(w io.Writer) {
	_, _ = io.WriteString(w, strings.TrimLeft(`
burnlink-cli sends a secret that can be opened once, encrypted on this machine.

Usage:
  burnlink-cli send [options]        read stdin (or --file), print one link
  burnlink-cli open [options] LINK   open a link, print or save the content
  burnlink-cli version

Options go before the link. Run a command with -h to list its options.

A passphrase is never a flag, which would show up in the process list. Set
BURNLINK_PASSPHRASE, or point BURNLINK_PASSPHRASE_FILE or --passphrase-file
at a file. A secret sent with a passphrase needs the same passphrase when it
is opened. open has no way to ask first: the server deletes a secret when it is
opened, so a missing or wrong passphrase means it is gone.
`, "\n"))
}

// newFlagSet returns a flag set that prints to stderr and does not exit.
func newFlagSet(name, synopsis string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: burnlink-cli %s %s\n\nOptions:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parse runs fs over args. A failure is already printed by the flag package.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	return nil
}

func httpClient(env Env) *http.Client {
	if env.HTTP != nil {
		return env.HTTP
	}
	return &http.Client{}
}
