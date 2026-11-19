// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/vue'
import { describe, expect, it } from 'vitest'

import { PBKDF2_ITERATIONS } from '../lib/crypto'
import SecurityView from './SecurityView.vue'

describe('SecurityView', () => {
  it('names every part of the protection it claims', () => {
    render(SecurityView)

    for (const heading of [
      /what is running today/i,
      /what the server has/i,
      /the link carries the key/i,
      /the encryption/i,
      /a passphrase on top/i,
      /one link, one read/i,
      /a request link keeps its key/i,
      /what is counted/i,
      /where this stops helping/i,
    ]) {
      expect(screen.getByRole('heading', { name: heading })).toBeVisible()
    }
  })

  it('states what is counted and what is not, and that no key or plaintext arrives', () => {
    render(SecurityView)

    const counting = screen.getByTestId('counting')
    expect(counting).toHaveTextContent(/no cookie/i)
    expect(counting).toHaveTextContent(/\/r\/\{id\}/)
    expect(counting).toHaveTextContent(/do not track/i)
    expect(counting).toHaveTextContent(/global privacy control/i)
    expect(counting).toHaveTextContent(/prefetch/i)
    expect(counting).toHaveTextContent(/query string/i)
    expect(counting).toHaveTextContent(/never receives a key or a plaintext/i)
  })

  it('names the key fragment and the one time read', () => {
    render(SecurityView)

    expect(screen.getAllByText(/key fragment/i)[0]).toBeVisible()
    expect(screen.getAllByText(/one read/i)[0]).toBeVisible()
  })

  it('says which parts are not running yet', () => {
    render(SecurityView)

    expect(screen.getByTestId('status')).toHaveTextContent(
      /no page of this site calls that API yet/i,
    )
    expect(screen.getByTestId('status')).toHaveTextContent(/not part of any page you can use/i)
  })

  it('names what the server holds and sees besides the payload', () => {
    render(SecurityView)

    expect(screen.getByText(/the address a request arrives from/i)).toBeVisible()
    expect(screen.getByText(/limits/i, { selector: 'dd' })).toBeVisible()
  })

  it('states the request link limits: unauthenticated senders and a swapped fragment', () => {
    render(SecurityView)

    expect(screen.getByText(/submissions are not authenticated/i)).toBeVisible()
    expect(screen.getByText(/replaces the fragment/i)).toBeVisible()
  })

  it('states the iteration count the code actually uses', () => {
    render(SecurityView)

    const spaced = PBKDF2_ITERATIONS.toLocaleString('en-US').replace(/,/g, ' ')
    expect(screen.getByText(new RegExp(spaced))).toBeVisible()
  })

  it('says what the service does not protect against', () => {
    render(SecurityView)

    expect(screen.getByText(/anyone who gets the link gets the secret/i)).toBeVisible()
    expect(screen.getByText(/could serve different code/i)).toBeVisible()
  })
})
