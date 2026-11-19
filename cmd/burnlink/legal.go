// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"net/http"

	"github.com/ostendorf-cloud/govue/language"
)

// legalLanguages and legalPages are the prerendered legal pages, the same set
// web/src/site.ts renders. There is no terms page: the site sells nothing, so
// LegalConfig.Terms stays off and /terms and /agb answer 404.
var (
	legalLanguages = []string{"de", "en"}
	legalPages     = []string{"imprint", "privacy"}
)

// mountLegal serves the prerendered legal pages at /<code>/<page> and
// registers govue's redirects from /imprint, /privacy and the German aliases.
//
// Each page is an exact pattern served from <code>/<page>/index.html in dist,
// so the mux never redirects between /de/imprint and /de/imprint/. A missing
// file fails startup instead of answering 404 at runtime.
//
// The redirects go on the mux itself, outside any wrapper: they need no
// session and no CSRF check. The page view counter wraps the whole mux and
// counts a 2xx page only, so a 302 alias is never reported.
func mountLegal(mux *http.ServeMux, dist fs.FS) error {
	for _, code := range legalLanguages {
		for _, page := range legalPages {
			file := code + "/" + page + "/index.html"
			if _, err := fs.Stat(dist, file); err != nil {
				return fmt.Errorf("burnlink: legal page %s is missing from the build: %w", file, err)
			}
			mux.HandleFunc("GET /"+code+"/"+page, func(w http.ResponseWriter, r *http.Request) {
				http.ServeFileFS(w, r, dist, file)
			})
		}
	}
	if err := language.HandleLegal(mux, language.LegalConfig{
		Config: language.Config{Languages: legalLanguages},
	}, nil); err != nil {
		return fmt.Errorf("burnlink: %w", err)
	}
	return nil
}
