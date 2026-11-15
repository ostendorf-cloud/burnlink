// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen, within } from '@testing-library/vue'
import { afterEach, describe, expect, it } from 'vitest'

import App from './App.vue'

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

  it('renders the security page on /security and names the key fragment and the one time read', () => {
    window.history.pushState({}, '', '/security')
    render(App)

    expect(screen.getByRole('heading', { name: 'How a secret stays secret' })).toBeVisible()
    expect(screen.getAllByText(/key fragment/i)[0]).toBeVisible()
    expect(screen.getByRole('heading', { name: 'One link, one read' })).toBeVisible()
    expect(screen.queryByRole('heading', { name: 'burnlink' })).not.toBeInTheDocument()
  })
})
