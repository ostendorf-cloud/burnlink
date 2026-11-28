// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// maxNameRunes caps a file name from the sender, as the page does.
const maxNameRunes = 120

// fallbackName is what a file name from the sender becomes when nothing
// usable is left of it.
const fallbackName = "secret"

// windowsReserved are device names that Windows opens instead of a file.
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// safeName turns a file name from the sender into one that is safe to create
// in a directory the receiver chose. The name is data. It mirrors the page's
// safeName: path separators and control characters become underscores,
// bidirectional controls are dropped, and the length is capped. A terminal
// has more traps than a browser download, so it goes further: a colon becomes
// an underscore, which on Windows names a data stream, and so do the other
// characters Windows refuses in a name. A name Windows treats as a device gets
// an underscore in front.
func safeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case strings.ContainsRune(`/\:<>"|?*`, r) || unicode.IsControl(r):
			b.WriteRune('_')
		case isBidiControl(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	runes := []rune(strings.TrimSpace(b.String()))
	if len(runes) > maxNameRunes {
		runes = runes[:maxNameRunes]
	}
	// Windows drops trailing dots and spaces, so "a." and "a" would collide.
	cleaned := strings.TrimRight(string(runes), ". ")
	if cleaned == "" {
		return fallbackName
	}
	stem, _, _ := strings.Cut(cleaned, ".")
	if windowsReserved[strings.ToUpper(strings.TrimSpace(stem))] {
		return "_" + cleaned
	}
	return cleaned
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// createUnique creates a new file for name in dir without ever replacing one.
// A taken name gets a number in front of the extension.
func createUnique(dir, name string) (*os.File, string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < 1000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
		path := filepath.Join(dir, candidate)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return f, path, nil
		}
		if !os.IsExist(err) {
			return nil, "", fmt.Errorf("create %s: %w", path, err)
		}
	}
	return nil, "", fmt.Errorf("no free name for %s in %s", name, dir)
}

// escapeForTerminal makes text safe to print to a terminal. A secret comes
// from someone else, and an escape sequence in it can rewrite the screen, set
// the title or fill the clipboard. Everything that is not a printable
// character, a newline or a tab is shown as an escape. It reports whether it
// changed anything.
func escapeForTerminal(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r':
			// A bare carriage return overwrites the line.
			b.WriteString(`\r`)
			changed = true
		case unicode.IsControl(r) || isBidiControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u{%x}`, r)
			changed = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), changed
}
