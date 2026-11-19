// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ostendorf-cloud/govue/language"

	"github.com/ostendorf-cloud/burnlink/internal/config"
)

// legalLanguages and legalPages are the prerendered legal pages, the same set
// web/src/site.ts renders. There is no terms page: the site sells nothing, so
// LegalConfig.Terms stays off and /terms and /agb answer 404.
var (
	legalLanguages = []string{"de", "en"}
	legalPages     = []string{"imprint", "privacy"}
)

// mountLegal serves the prerendered legal pages at /<code>/<page>, plus
// /robots.txt and /sitemap.xml, and registers govue's redirects from
// /imprint, /privacy and the German aliases.
//
// The build bakes config.DefaultSiteURL into the canonical and hreflang
// links of the pages and into the sitemap and robots files. Each of those
// files is read once here and has that origin replaced with site, so the
// published URLs follow SITE_URL.
//
// Each page is an exact pattern, so the mux never redirects between
// /de/imprint and /de/imprint/. A missing file fails startup instead of
// answering 404 at runtime.
//
// The redirects go on the mux itself, outside any wrapper: they need no
// session and no CSRF check. The page view counter wraps the whole mux and
// counts a 2xx page only, so a 302 alias is never reported.
func mountLegal(mux *http.ServeMux, dist fs.FS, site *url.URL) error {
	origin := strings.TrimSuffix(site.String(), "/")
	files := map[string]string{}
	for _, code := range legalLanguages {
		for _, page := range legalPages {
			files["/"+code+"/"+page] = code + "/" + page + "/index.html"
		}
	}
	files["/robots.txt"] = "robots.txt"
	files["/sitemap.xml"] = "sitemap.xml"

	for pattern, file := range files {
		body, err := fs.ReadFile(dist, file)
		if err != nil {
			return fmt.Errorf("burnlink: %s is missing from the build: %w", file, err)
		}
		body = bytes.ReplaceAll(body, []byte(config.DefaultSiteURL), []byte(origin))
		mux.HandleFunc("GET "+pattern, func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, file, time.Time{}, bytes.NewReader(body))
		})
	}
	if err := language.HandleLegal(mux, language.LegalConfig{
		Config: language.Config{Languages: legalLanguages},
	}, nil); err != nil {
		return fmt.Errorf("burnlink: %w", err)
	}
	return nil
}
