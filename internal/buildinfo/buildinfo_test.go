// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package buildinfo

import "testing"

func TestReadNeverReturnsEmptyFields(t *testing.T) {
	info := Read()
	if info.Version == "" || info.Commit == "" || info.GoVersion == "" {
		t.Errorf("Read() = %+v, want no empty field", info)
	}
}

func TestReadPrefersLinkTimeValues(t *testing.T) {
	oldVersion, oldCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = oldVersion, oldCommit })
	Version, Commit = "1.2.3", "abc123"

	info := Read()
	if info.Version != "1.2.3" || info.Commit != "abc123" {
		t.Errorf("Read() = %+v, want the link time values", info)
	}
}
