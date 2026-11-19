// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates this service's own environment once,
// in main, aggregating every problem into one error.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/ostendorf-cloud/govue/analytics"
	"github.com/ostendorf-cloud/govue/clientip"
	"github.com/ostendorf-cloud/govue/envconf"
	"github.com/ostendorf-cloud/govue/logging"
)

// DefaultSiteURL is this site's own public origin, used when SITE_URL is
// unset. It is also the origin the web build bakes into the prerendered
// legal pages, sitemap.xml and robots.txt, which the server rewrites to
// SiteURL when the two differ.
const DefaultSiteURL = "https://burnlink.de"

// Config is every setting this binary reads from the environment. The
// store's credentials are its only secret-shaped fields, and each has a
// _FILE twin; see Store.
type Config struct {
	// Addr is the public HTTP listener's address.
	Addr string
	// AdminAddr is govue's admin listener's address: /healthz, /readyz and
	// /metrics, reached only from inside the cluster, never through the
	// chart's own Ingress.
	AdminAddr string
	LogLevel  slog.Level

	// TrustedProxies are the TCP peers whose X-Forwarded-For entry
	// internal/webapp's client address resolution trusts, fed into
	// clientip.NewResolver for the access log and the rate limit. Empty means
	// every request is attributed to its TCP peer, the secure default
	// behind no proxy at all, but the wrong one behind the chart's own
	// Ingress, where every submitter would otherwise collapse onto the
	// ingress pod's own address.
	TrustedProxies []netip.Prefix

	// Store is the Redis-compatible store's address and credentials.
	Store Store

	// Secrets are the size and lifetime limits of a stored secret.
	Secrets Secrets
	// RateLimit is the per client address budget of the secret endpoints.
	RateLimit RateLimit

	// Umami is the page view counting of govue's analytics package. It is
	// off unless UMAMI_URL and UMAMI_WEBSITE_ID are both set.
	Umami analytics.Config
	// SiteURL is the public origin of the site: the base of every absolute
	// URL it publishes and, through its Hostname, the hostname reported to
	// Umami for every view. It comes from SITE_URL, never from the Host
	// header of a request.
	SiteURL *url.URL
}

// Load reads every setting through envconf, so a misconfigured deployment
// reports every mistake on the first start instead of one per restart.
func Load(getenv func(string) string) (Config, error) {
	l := envconf.New(getenv)
	resolved := resolvedGetenv(getenv)

	cfg := Config{
		Addr:      l.String("ADDR", ":8080"),
		AdminAddr: l.String("ADMIN_ADDR", ":8081"),
	}

	var problems []error
	cfg.Store, problems = loadStore(l, problems)
	cfg.Secrets, cfg.RateLimit, problems = loadSecrets(l, problems)
	level, err := logging.Level(l.String("LOG_LEVEL", "info"))
	if err != nil {
		problems = append(problems, err)
	}
	cfg.LogLevel = level

	trustedProxies, err := clientip.ParseCIDRs(resolved("TRUSTED_PROXIES"))
	if err != nil {
		problems = append(problems, err)
	}
	cfg.TrustedProxies = trustedProxies

	cfg.SiteURL = loadSiteURL(l, &problems)
	umami, err := analytics.LoadConfig(getenv)
	if err != nil {
		problems = append(problems, err)
	}
	cfg.Umami = umami

	if err := errors.Join(append(problems, l.Err())...); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// loadSiteURL reads SITE_URL: an absolute origin with no path, query or
// fragment, https unless the host is localhost. It is never empty, the
// default being DefaultSiteURL, so Umami always has a hostname.
func loadSiteURL(l *envconf.Loader, problems *[]error) *url.URL {
	u := l.URL("SITE_URL", DefaultSiteURL)
	switch {
	case u == nil:
		// envconf recorded the problem.
	case u.Path != "":
		*problems = append(*problems, fmt.Errorf("SITE_URL must be an origin without a path, got %q", u.String()))
	case u.Scheme == "http" && !isLocalhost(u.Hostname()):
		*problems = append(*problems, fmt.Errorf("SITE_URL must use https unless the host is localhost, got %q", u.String()))
	}
	return u
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// resolvedGetenv defaults a nil lookup function to the real process
// environment, the same default envconf.New applies, so clientip.ParseCIDRs
// never has to special case a nil getenv.
func resolvedGetenv(getenv func(string) string) func(string) string {
	if getenv == nil {
		return os.Getenv
	}
	return getenv
}
