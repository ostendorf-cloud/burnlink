// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The share and the reveal view over the real API client and the real
// secrets-api, with only fetch replaced by an in-memory server. Every request
// the browser would send is recorded, so the zero knowledge claim is checked
// against what actually goes over the wire, not against a mocked call.

import { render, screen } from '@testing-library/vue'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type * as ApiClientModule from '../lib/api-client'
import { encodeBase64, encodeBase64url } from '../lib/crypto'
import RevealSecretView from './RevealSecretView.vue'
import ShareSecret from './ShareSecret.vue'

interface Recorded {
  method: string
  url: string
  headers: string
  body: string
}

const wire = vi.hoisted(() => {
  const requests: Recorded[] = []
  const vault = new Map<string, string>()
  let counter = 0

  function json(status: number, value: unknown): Response {
    return new Response(JSON.stringify(value), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // HEAD answers carry no body, also the refusal.
  function handle(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = String(init?.method)
    const body = typeof init?.body === 'string' ? init.body : ''
    requests.push({ method, url, headers: JSON.stringify(init?.headers ?? {}), body })

    const path = new URL(url, 'http://localhost').pathname
    const id = /^\/api\/v1\/secrets\/([^/]+)/.exec(path)?.[1] ?? ''
    if (method === 'GET' && path === '/api/v1/config') {
      return Promise.resolve(
        json(200, {
          maxCiphertextBytes: 65536,
          lifetime: { minSeconds: 60, maxSeconds: 604800, defaultSeconds: 86400 },
        }),
      )
    }
    if (method === 'POST' && path === '/api/v1/secrets') {
      const newID = 'wire' + String(counter++).padStart(18, '0')
      vault.set(newID, (JSON.parse(body) as { ciphertext: string }).ciphertext)
      return Promise.resolve(json(201, { id: newID, expiresAt: '2030-01-01T00:00:00Z' }))
    }
    if (method === 'HEAD' && vault.has(id)) return Promise.resolve(new Response(null))
    if (method === 'POST' && path.endsWith('/open') && vault.has(id)) {
      const ciphertext = vault.get(id)
      vault.delete(id)
      return Promise.resolve(json(200, { ciphertext }))
    }
    return Promise.resolve(
      method === 'HEAD'
        ? new Response(null, { status: 404 })
        : json(404, { error: { code: 'not_found', message: 'secret not available' } }),
    )
  }

  return { requests, vault, handle }
})

vi.mock('../lib/api-client', async (importOriginal) => {
  const actual = await importOriginal<typeof ApiClientModule>()
  const { createClient } = await import('@ostendorf-cloud/govue')
  return {
    ...actual,
    apiClient: createClient({ fetch: wire.handle }),
    headClient: actual.createHeadClient(wire.handle),
  }
})

beforeEach(() => {
  wire.requests.length = 0
  wire.vault.clear()
  window.history.pushState({}, '', '/')
})

describe('what goes over the wire', () => {
  it('sends the key, the passphrase and the plaintext in no request', async () => {
    const secret = 'prod database password hunter2'
    const passphrase = 'open sesame'

    const share = render(ShareSecret)
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), secret)
    await userEvent.type(screen.getByLabelText('Passphrase (optional)'), passphrase)
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    const link = new URL((await screen.findByLabelText<HTMLInputElement>('Secret link')).value)
    share.unmount()

    const key = link.hash.slice(1)
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const keyBytes = Uint8Array.from(atob(key.replace(/-/g, '+').replace(/_/g, '/') + '='), (c) =>
      c.charCodeAt(0),
    )
    // The same key in every encoding a request could plausibly carry it in.
    const needles = [key, encodeBase64url(keyBytes), encodeBase64(keyBytes), secret, passphrase]

    window.history.pushState({}, '', link.pathname + link.hash)
    const id = decodeURIComponent(link.pathname.split('/')[2])
    render(RevealSecretView, { props: { id } })
    await userEvent.click(await screen.findByRole('button', { name: 'Reveal the secret' }))
    await userEvent.type(await screen.findByLabelText('Passphrase'), passphrase + '{Enter}')
    expect(await screen.findByTestId('revealed-text')).toHaveTextContent(secret)

    expect(wire.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /api/v1/config',
      'POST /api/v1/secrets',
      `HEAD /api/v1/secrets/${id}`,
      `POST /api/v1/secrets/${id}/open`,
    ])
    for (const request of wire.requests) {
      const sent = request.url + request.headers + request.body
      for (const needle of needles) expect(sent).not.toContain(needle)
      expect(request.url).not.toContain('#')
    }
    // The check carries nothing but its address.
    expect(wire.requests[2].body).toBe('')
  })

  it('leaves the secret in the vault when a link is only checked', async () => {
    const share = render(ShareSecret)
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'preview me')
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    const link = new URL((await screen.findByLabelText<HTMLInputElement>('Secret link')).value)
    share.unmount()

    window.history.pushState({}, '', link.pathname + link.hash)
    const id = decodeURIComponent(link.pathname.split('/')[2])
    for (let i = 0; i < 3; i++) {
      const view = render(RevealSecretView, { props: { id } })
      expect(await screen.findByRole('button', { name: 'Reveal the secret' })).toBeVisible()
      view.unmount()
    }

    expect(wire.vault.size).toBe(1)
    expect(wire.requests.filter((r) => r.url.endsWith('/open'))).toHaveLength(0)
    expect(wire.requests.filter((r) => r.method === 'HEAD')).toHaveLength(3)
  })

  it('reports an unknown link from the check without sending a reveal', async () => {
    const key = 'A'.repeat(43)
    window.history.pushState({}, '', '/s/wire000000000000000099#' + key)
    render(RevealSecretView, { props: { id: 'wire000000000000000099' } })

    expect(await screen.findByText('This secret is not available')).toBeVisible()
    expect(wire.requests.map((r) => r.method)).toEqual(['HEAD'])
  })
})
