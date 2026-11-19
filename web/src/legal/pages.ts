// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { h, type Component } from 'vue'
import type { LegalPages } from '@ostendorf-cloud/govue'

import LegalView from './LegalView.vue'

// The legal pages of burnlink. There is no terms entry: the site sells
// nothing, so govue builds no terms page and the Go server registers no
// /terms or /agb.
export const legalPages: LegalPages<Component> = {
  imprint: { render: () => h(LegalView, { page: 'imprint' }) },
  privacy: { render: () => h(LegalView, { page: 'privacy' }) },
}

const LEGAL_PATH = /^\/(de|en)\/(imprint|privacy)$/

/** The legal page a path names, or null for any other path. */
export function legalPageForPath(pathname: string): 'imprint' | 'privacy' | null {
  const match = LEGAL_PATH.exec(pathname)
  return match ? (match[2] as 'imprint' | 'privacy') : null
}
