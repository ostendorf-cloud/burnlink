// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The SSR entry `govue-prerender --out-dir` loads. It renders only the legal
// pages, in both languages, plus sitemap.xml and robots.txt. The app pages
// (/, /security, /r/<id>) stay client rendered: they are not in the route
// table, so no /de/ or /en/ copy of them exists.

import type { Component } from 'vue'
import { createGovueI18n, legalRouteDefs, legalRoutes } from '@ostendorf-cloud/govue'
import type { LocalizedRoute } from '@ostendorf-cloud/govue'
import { localizedFiles, render, type PrerenderFile } from '@ostendorf-cloud/govue/server'

import { legalPages } from './legal/pages'

export const ORIGIN = 'https://burnlink.de'

// The URLs of a secret and of a request link are secrets themselves, and the
// API is no page: no crawler has a reason to visit them. The legal pages stay
// crawlable.
export const ROBOTS = [
  'User-agent: *',
  'Disallow: /r/',
  'Disallow: /s/',
  'Disallow: /api/',
  'Allow: /de/imprint',
  'Allow: /en/imprint',
  'Allow: /de/privacy',
  'Allow: /en/privacy',
  `Sitemap: ${ORIGIN}/sitemap.xml`,
  '',
].join('\n')

const routes = legalRouteDefs(legalPages)
const records = legalRoutes(legalPages)

function componentFor(variant: LocalizedRoute): Component {
  const record = records.find((r) => r.path === variant.path)
  if (!record) {
    throw new Error(`burnlink: no legal page for ${variant.path}`)
  }
  return record.component
}

export async function files(template: string): Promise<PrerenderFile[]> {
  const pages = await localizedFiles(routes, {
    origin: ORIGIN,
    template,
    render: (variant) =>
      render(componentFor(variant), {
        setup: (app) => {
          app.use(createGovueI18n({ locale: variant.locale }))
        },
      }),
  })
  return [...pages, { path: 'robots.txt', content: ROBOTS }]
}
