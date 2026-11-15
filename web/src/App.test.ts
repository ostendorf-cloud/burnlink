// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen, within } from '@testing-library/vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App.vue'

// jsdom has no IndexedDB, and the request link view reads it on mount.
vi.mock('./lib/request-link-keys', () => ({
  hasOwnerKey: vi.fn().mockResolvedValue(false),
  loadOwnerKey: vi.fn(),
}))

afterEach(() => {
  window.history.pushState({}, '', '/')
})

describe('App', () => {
  it('renders the repository name as the page heading', () => {
    render(App)

    expect(screen.getByRole('heading', { name: 'burnlink' })).toBeVisible()
  })

  it('renders the one-line description as the placeholder lead', () => {
    render(App)

    expect(
      screen.getByText(
        'One time secret sharing: the browser encrypts, the server hands it out exactly once.',
      ),
    ).toBeVisible()
  })

  it('links the security page from the header and the footer', () => {
    render(App)

    const header = screen.getByRole('navigation', { name: 'Main' })
    expect(header).toHaveTextContent('How the encryption works')
    expect(within(header).getByRole('link', { name: 'How the encryption works' })).toHaveAttribute(
      'href',
      '/security',
    )
    const footer = screen.getByRole('navigation', { name: 'Footer' })
    expect(footer.querySelector('a')).toHaveAttribute('href', '/security')
  })

  it('offers a skip link and marks only the real current page', () => {
    window.history.pushState({}, '', '/security')
    render(App)

    expect(screen.getByRole('link', { name: 'Skip to content' })).toHaveAttribute('href', '#main')
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(within(nav).getByRole('link', { name: 'How the encryption works' })).toHaveAttribute(
      'aria-current',
      'page',
    )
    expect(within(nav).getByRole('link', { name: 'Home' })).not.toHaveAttribute('aria-current')
    expect(screen.queryByRole('link', { name: 'Send a secret' })).not.toBeInTheDocument()
  })

  it.each(['/', '/security', '/r/abc'])(
    'gives the skip link a target, one main landmark with id main, on %s',
    (path) => {
      window.history.pushState({}, '', path)
      const { container } = render(App)

      const target = screen.getByRole('link', { name: 'Skip to content' }).getAttribute('href')
      expect(target).toBe('#main')
      expect(screen.getAllByRole('main')).toHaveLength(1)
      expect(container.querySelector('main#main')).not.toBeNull()
    },
  )

  it('renders the security page on /security and names the key fragment and the one time read', () => {
    window.history.pushState({}, '', '/security')
    render(App)

    expect(screen.getByRole('heading', { name: 'How a secret stays secret' })).toBeVisible()
    expect(screen.getAllByText(/key fragment/i)[0]).toBeVisible()
    expect(screen.getByRole('heading', { name: 'One link, one read' })).toBeVisible()
    expect(screen.queryByRole('heading', { name: 'burnlink' })).not.toBeInTheDocument()
  })
})
