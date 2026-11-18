// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo reports which build is running. A release build can set
// Version and Commit through -ldflags "-X"; without them the Go toolchain's
// own embedded build information answers.
package buildinfo

import "runtime/debug"

// Version and Commit are set at link time with
// -ldflags "-X github.com/ostendorf-cloud/burnlink/internal/buildinfo.Version=...".
// Empty means the build information of the Go toolchain is used instead.
var (
	Version string
	Commit  string
)

// Info is what the build endpoint reports.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
}

// Read returns the running build. Fields the build does not carry are
// "unknown", never empty, so a client can tell "not reported" from a bug.
func Read() Info {
	info := Info{Version: Version, Commit: Commit}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = bi.GoVersion
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		if info.Commit == "" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					info.Commit = s.Value
				}
			}
		}
	}
	if info.Version == "" {
		info.Version = "unknown"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.GoVersion == "" {
		info.GoVersion = "unknown"
	}
	return info
}
