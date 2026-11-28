// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Command burnlink-cli sends a secret from a terminal and opens one, with the
// same encryption as the page. All behaviour is in internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ostendorf-cloud/burnlink/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], cli.Env{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		Getenv:           os.Getenv,
		StdinIsTerminal:  isTerminal(os.Stdin),
		StdoutIsTerminal: isTerminal(os.Stdout),
	})
	stop()
	os.Exit(code)
}

// isTerminal reports whether f is a character device, which is what a
// terminal is. It also holds for /dev/null, which only costs a hint.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
