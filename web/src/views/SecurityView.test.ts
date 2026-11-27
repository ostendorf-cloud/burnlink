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

  it('says that a webhook target is stored, learned, and not guaranteed', () => {
    render(SecurityView)

    const notification = screen.getByTestId('notification')
    expect(notification).toHaveTextContent(/in plain text/i)
    expect(notification).toHaveTextContent(/learns the address/i)
    expect(notification).toHaveTextContent(/never the secret/i)
    expect(notification).toHaveTextContent(/port 443/i)
    expect(notification).toHaveTextContent(/a notification can be lost/i)
    expect(screen.getByTestId('status')).toHaveTextContent(
      /notification by mail does not exist yet/i,
    )
  })

  it('names the key fragment and the one time read', () => {
    render(SecurityView)

    expect(screen.getAllByText(/key fragment/i)[0]).toBeVisible()
    expect(screen.getAllByText(/one read/i)[0]).toBeVisible()
  })

  it('says which parts are not running yet', () => {
    render(SecurityView)

    const status = screen.getByTestId('status')
    expect(status).toHaveTextContent(/sharing and revealing an ordinary secret runs/i)
    expect(status).toHaveTextContent(/not running yet: the request link/i)
    expect(status).not.toHaveTextContent(/no page of this site calls/i)
  })

  it('counts the secret link by its pattern and says opening is not counted', () => {
    render(SecurityView)

    const counting = screen.getByTestId('counting')
    expect(counting).toHaveTextContent(/\/s\/\{id\}/)
    expect(counting).toHaveTextContent(/opening the secret is a call to the api and is not/i)
  })

  it('tells the reader a preview does not use a link up, and what a wrong passphrase costs', () => {
    render(SecurityView)

    expect(screen.getByText(/does not use the link up/i)).toBeVisible()
    expect(screen.getByText(/gone for good/i)).toBeVisible()
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

  it("names the recipient's history, not the sender's, and that replaceState keeps the entry", () => {
    render(SecurityView)

    const item = screen.getByText(/recipient's browser records the whole link/i)
    expect(item).toBeVisible()
    expect(item.textContent).toMatch(/does not remove that history entry/)
    expect(item.textContent).toMatch(/never revealed can\s+still be opened/)
    expect(screen.queryByText(/sender's browser history/i)).not.toBeInTheDocument()
  })
})
