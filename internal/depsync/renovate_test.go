// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package depsync

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// renovateConfigPath is the repository's Renovate configuration, relative to this package.
const renovateConfigPath = "../../renovate.json"

// renovateConfig holds the parts of renovate.json these checks read.
type renovateConfig struct {
	Extends        []string `json:"extends"`
	CustomManagers []struct {
		CustomType          string   `json:"customType"`
		ManagerFilePatterns []string `json:"managerFilePatterns"`
		MatchStrings        []string `json:"matchStrings"`
		DepNameTemplate     string   `json:"depNameTemplate"`
		DatasourceTemplate  string   `json:"datasourceTemplate"`
	} `json:"customManagers"`
	PackageRules []struct {
		Description       string            `json:"description"`
		AllowedVersions   string            `json:"allowedVersions"`
		MatchPackageNames []string          `json:"matchPackageNames"`
		MatchManagers     []string          `json:"matchManagers"`
		GroupName         string            `json:"groupName"`
		Constraints       map[string]string `json:"constraints"`
	} `json:"packageRules"`
}

func readRenovateConfig(t *testing.T) renovateConfig {
	t.Helper()

	raw, err := os.ReadFile(renovateConfigPath)
	if err != nil {
		t.Fatalf("read renovate.json: %v", err)
	}

	var cfg renovateConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse renovate.json: %v", err)
	}
	return cfg
}

// misePnpm reads the pnpm pin of mise.toml.
func misePnpm(t *testing.T) string {
	t.Helper()

	mise, err := os.ReadFile("../../mise.toml")
	if err != nil {
		t.Fatalf("read mise.toml: %v", err)
	}
	pin := regexp.MustCompile(`(?m)^pnpm = "([^"]+)"`).FindStringSubmatch(string(mise))
	if pin == nil {
		t.Fatal(`mise.toml has no 'pnpm = "<version>"' line`)
	}
	return pin[1]
}

// TestRenovateExtendsGovueLockfilePreset fails when renovate.json drops the shared preset
// that regenerates web/pnpm-lock.yaml. Without it a govue pull request leaves the lock file
// stale and the frozen install fails.
func TestRenovateExtendsGovueLockfilePreset(t *testing.T) {
	t.Parallel()

	const preset = "github>ostendorf-cloud/workflows:govue-lockfile#v0"
	if !slices.Contains(readRenovateConfig(t).Extends, preset) {
		t.Fatalf("renovate.json does not extend %q", preset)
	}
}

// TestRenovateGroupsGovueHalves fails when renovate.json no longer puts the Go module and
// the npm package of govue into one group. Without the group Renovate raises the halves in
// separate pull requests, and each fails check:govue-version.
func TestRenovateGroupsGovueHalves(t *testing.T) {
	t.Parallel()

	cfg := readRenovateConfig(t)

	var groups []string
	for _, rule := range cfg.PackageRules {
		if rule.GroupName == "" {
			continue
		}
		if slices.Contains(rule.MatchPackageNames, goModulePath) &&
			slices.Contains(rule.MatchPackageNames, "ostendorf-cloud/govue") {
			groups = append(groups, rule.GroupName)
		}
	}

	if len(groups) != 1 {
		t.Fatalf("want exactly one packageRules group naming both %q and %q, got %d: %v",
			goModulePath, "ostendorf-cloud/govue", len(groups), groups)
	}
	if groups[0] != "govue" {
		t.Fatalf("govue group is named %q, want %q", groups[0], "govue")
	}
}

// TestRenovateManagerReadsGovueSpecifier fails when the custom manager's expression no
// longer extracts the tag from web/package.json's real specifier. Renovate's own npm
// manager skips that specifier ("unversioned-reference") because of the "&path:/web"
// suffix, so this manager is the only way the npm half is ever updated.
func TestRenovateManagerReadsGovueSpecifier(t *testing.T) {
	t.Parallel()

	cfg := readRenovateConfig(t)

	raw, err := os.ReadFile(packageJSONPath)
	if err != nil {
		t.Fatalf("read web/package.json: %v", err)
	}
	wantTag, err := packageJSONGovueTag(t)
	if err != nil {
		t.Fatalf("resolve the tag in web/package.json: %v", err)
	}

	for _, manager := range cfg.CustomManagers {
		if manager.CustomType != "regex" || manager.DepNameTemplate != "ostendorf-cloud/govue" {
			continue
		}
		if manager.DatasourceTemplate != "github-tags" {
			t.Fatalf("datasourceTemplate = %q, want github-tags", manager.DatasourceTemplate)
		}
		if !slices.Contains(manager.ManagerFilePatterns, "/^web/package\\.json$/") {
			t.Fatalf("managerFilePatterns = %v, want web/package.json", manager.ManagerFilePatterns)
		}
		if len(manager.MatchStrings) != 1 {
			t.Fatalf("want one matchStrings entry, got %d", len(manager.MatchStrings))
		}

		re := regexp.MustCompile(manager.MatchStrings[0])
		group := re.SubexpIndex("currentValue")
		if group < 0 {
			t.Fatalf("matchStrings %q has no named group currentValue", manager.MatchStrings[0])
		}
		match := re.FindSubmatch(raw)
		if match == nil {
			t.Fatalf("matchStrings %q finds nothing in web/package.json", manager.MatchStrings[0])
		}
		got := string(match[group])
		if got != wantTag {
			t.Fatalf("custom manager extracts tag %q, web/package.json pins %q", got, wantTag)
		}
		return
	}

	t.Fatal("renovate.json has no regex custom manager for ostendorf-cloud/govue")
}

// dockerfilePath is the Dockerfile, relative to this package.
const dockerfilePath = "../../Dockerfile"

// dockerfilePnpmArg matches the PNPM_VERSION argument of the Dockerfile.
var dockerfilePnpmArg = regexp.MustCompile(`(?m)^ARG PNPM_VERSION=(\S+)$`)

// TestDockerfilePnpmMatchesMise fails when the Dockerfile's PNPM_VERSION differs from the
// pnpm pin in mise.toml. The image must read the lock file with the pnpm that wrote it.
func TestDockerfilePnpmMatchesMise(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	arg := dockerfilePnpmArg.FindSubmatch(raw)
	if arg == nil {
		t.Fatal("Dockerfile has no 'ARG PNPM_VERSION=<version>' line")
	}
	if got, pin := string(arg[1]), misePnpm(t); got != pin {
		t.Fatalf("Dockerfile PNPM_VERSION is %s, mise.toml pins %s: they move together", got, pin)
	}
	if regexp.MustCompile(`corepack prepare pnpm@\d`).Match(raw) {
		t.Fatal("Dockerfile pins pnpm as a literal in corepack prepare, want the PNPM_VERSION argument")
	}
}

// TestRenovateReadsDockerfilePnpm fails when no regex custom manager of renovate.json
// extracts the npm datasource, the name pnpm and the mise.toml version from the Dockerfile's
// PNPM_VERSION argument. Renovate's named group syntax, (?<name>...), is also Go's.
func TestRenovateReadsDockerfilePnpm(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	pin := misePnpm(t)

	for _, manager := range readRenovateConfig(t).CustomManagers {
		if manager.CustomType != "regex" || !slices.Contains(manager.ManagerFilePatterns, "/^Dockerfile$/") {
			continue
		}
		for _, expr := range manager.MatchStrings {
			re, err := regexp.Compile(expr)
			if err != nil {
				t.Fatalf("matchStrings %q does not compile: %v", expr, err)
			}
			match := re.FindStringSubmatch(string(raw))
			if match == nil {
				continue
			}
			named := map[string]string{}
			for i, name := range re.SubexpNames() {
				if name != "" {
					named[name] = match[i]
				}
			}
			if named["datasource"] != "npm" || named["depName"] != "pnpm" || named["currentValue"] != pin {
				t.Fatalf("Dockerfile manager extracts %v, want datasource npm, depName pnpm, version %s", named, pin)
			}
			return
		}
	}

	t.Fatal("no regex custom manager of renovate.json matches the Dockerfile's PNPM_VERSION argument")
}

// TestRenovateGroupsPnpmPins fails when renovate.json has no rule that groups the pnpm pin
// of mise.toml with the Dockerfile argument and the govue rule's constraints.pnpm. Without
// the group a pnpm bump of mise.toml alone breaks the tests of those pins.
func TestRenovateGroupsPnpmPins(t *testing.T) {
	t.Parallel()

	for _, rule := range readRenovateConfig(t).PackageRules {
		if !slices.Contains(rule.MatchPackageNames, "pnpm") {
			continue
		}
		for _, manager := range []string{"mise", "custom.regex", "renovate-config"} {
			if !slices.Contains(rule.MatchManagers, manager) {
				t.Fatalf("the pnpm rule matches managers %v, want %q among them", rule.MatchManagers, manager)
			}
		}
		if rule.GroupName != "pnpm" {
			t.Fatalf("the pnpm rule groups as %q, want %q", rule.GroupName, "pnpm")
		}
		return
	}

	t.Fatal("renovate.json has no package rule for pnpm")
}

// TestRenovateGovueConstraintMatchesMise fails when the govue rule's constraints.pnpm
// differs from the pnpm pin in mise.toml. The post upgrade command of the lockfile preset
// runs with that pnpm, so the lock file must be written by the version mise.toml pins.
func TestRenovateGovueConstraintMatchesMise(t *testing.T) {
	t.Parallel()

	cfg := readRenovateConfig(t)
	pin := misePnpm(t)

	for _, rule := range cfg.PackageRules {
		if !slices.Contains(rule.MatchPackageNames, goModulePath) {
			continue
		}
		got, ok := rule.Constraints["pnpm"]
		if !ok {
			t.Fatal("the govue rule has no constraints.pnpm")
		}
		if got != pin {
			t.Fatalf("constraints.pnpm is %s, mise.toml pins %s: they move together", got, pin)
		}
		return
	}

	t.Fatal("renovate.json has no package rule for govue")
}

// TestRenovateHoldsTypescriptBelowSeven fails when renovate.json loses the rule that keeps
// TypeScript below 7, or changes its range, or drops the description that names when to
// remove it. typescript-eslint and vue-tsc do not support 7 yet, so a 7.0 pull request
// would fail on import.
func TestRenovateHoldsTypescriptBelowSeven(t *testing.T) {
	t.Parallel()

	for _, rule := range readRenovateConfig(t).PackageRules {
		if !slices.Contains(rule.MatchPackageNames, "typescript") {
			continue
		}
		if rule.AllowedVersions != "<7" {
			t.Fatalf("the typescript rule allows %q, want %q", rule.AllowedVersions, "<7")
		}
		if !strings.Contains(rule.Description, "Remove this rule when") {
			t.Fatalf("the typescript rule's description %q does not name the condition to remove it", rule.Description)
		}
		return
	}

	t.Fatal("renovate.json has no package rule for typescript")
}
