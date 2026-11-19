// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/vue'
import { createGovueI18n } from '@ostendorf-cloud/govue'
import { describe, expect, it } from 'vitest'

import { files, ORIGIN } from '../site'
import LegalView from './LegalView.vue'
import { legalPageForPath } from './pages'

function mount(page: 'imprint' | 'privacy', locale: 'de' | 'en') {
  return render(LegalView, {
    props: { page },
    global: { plugins: [createGovueI18n({ locale, detect: false })] },
  })
}

const dispute = /Verbraucherstreit|Schlichtung|dispute resolution|arbitration/i

describe('legal pages', () => {
  it.each(['de', 'en'] as const)(
    'the %s imprint names the operator and no dispute section',
    (locale) => {
      const { container } = mount('imprint', locale)

      const text = container.textContent ?? ''
      for (const fact of ['Simon Ostendorf', 'Frankenstr. 8', '52070 Aachen', 'DE362164357']) {
        expect(text).toContain(fact)
      }
      expect(screen.getByRole('link', { name: 'info@burnlink.de' })).toHaveAttribute(
        'href',
        'mailto:info@burnlink.de',
      )
      expect(screen.getByRole('link', { name: '+49 1573 0971784' })).toBeVisible()
      expect(text).not.toMatch(dispute)
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    },
  )

  it.each(['de', 'en'] as const)(
    'the %s privacy text states what is counted and links the security page',
    (locale) => {
      const { container } = mount('privacy', locale)

      const text = container.textContent ?? ''
      expect(text).toContain('/r/{id}')
      expect(text).toContain('/api')
      expect(text).toContain('48')
      expect(text).toContain('Umami')
      expect(text).toContain('info@burnlink.de')
      expect(text).not.toMatch(dispute)
      const security = container.querySelector('main a[href="/security"]')
      expect(security).not.toBeNull()
    },
  )

  it('the English pages point to the binding German text', () => {
    mount('imprint', 'en')
    expect(screen.getByRole('link', { name: /German version/ })).toHaveAttribute(
      'href',
      '/de/imprint',
    )
  })

  it.each([
    ['de', 'imprint', '/de/imprint', '/de/privacy'],
    ['en', 'privacy', '/en/imprint', '/en/privacy'],
  ] as const)(
    'the footer of %s %s links both legal pages of its language',
    (locale, page, imprint, privacy) => {
      const { container } = mount(page, locale)

      const footer = container.querySelector('footer nav')
      expect(footer).not.toBeNull()
      if (!footer) return
      expect(footer.querySelector(`a[href="${imprint}"]`)).not.toBeNull()
      expect(footer.querySelector(`a[href="${privacy}"]`)).not.toBeNull()
      expect(footer.querySelector('a[href$="/terms"]')).toBeNull()
    },
  )

  it('tells a legal path from every other path', () => {
    expect(legalPageForPath('/de/imprint')).toBe('imprint')
    expect(legalPageForPath('/en/privacy')).toBe('privacy')
    for (const path of [
      '/',
      '/security',
      '/r/abc',
      '/de/terms',
      '/fr/imprint',
      '/de/imprint/',
      '/imprint',
    ]) {
      expect(legalPageForPath(path)).toBeNull()
    }
  })
})

describe('prerender file list', () => {
  const template = [
    '<!doctype html><html lang="en"><head><!--app-head--></head>',
    '<body><div id="app"><!--app-html--></div></body></html>',
  ].join('')

  it('holds the four legal pages, the sitemap and robots, and no terms page', async () => {
    const list = await files(template)

    expect(list.map((f) => f.path).sort()).toEqual([
      'de/imprint/index.html',
      'de/privacy/index.html',
      'en/imprint/index.html',
      'en/privacy/index.html',
      'robots.txt',
      'sitemap.xml',
    ])
    const sitemap = list.find((f) => f.path === 'sitemap.xml')?.content ?? ''
    expect(sitemap).not.toContain('terms')
    expect(sitemap).toContain(`${ORIGIN}/de/imprint`)
    expect(list.find((f) => f.path === 'robots.txt')?.content).toContain(`${ORIGIN}/sitemap.xml`)
  })
})
