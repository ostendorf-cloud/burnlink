// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The share and the reveal view together over an in-memory stand in for the
// server: real crypto, real components, only the network call replaced.

import { render, screen, waitFor } from '@testing-library/vue'
import userEvent from '@testing-library/user-event'
import { ApiError } from '@ostendorf-cloud/govue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { encodeBase64, type Bytes } from '../lib/crypto'
import RevealSecretView from './RevealSecretView.vue'
import ShareSecret from './ShareSecret.vue'

vi.mock('../lib/secrets-api', () => ({
  getConfig: vi.fn(),
  storeSecret: vi.fn(),
  openSecret: vi.fn(),
}))

import { getConfig, openSecret, storeSecret } from '../lib/secrets-api'

// What the server would hold, and every request body it was sent.
let server: Map<string, Bytes>
let received: string[]
let opens: number

function notFound() {
  return new ApiError({ code: 'not_found', message: 'secret not available', status: 404 })
}

beforeEach(() => {
  server = new Map()
  received = []
  opens = 0
  window.history.pushState({}, '', '/')
  vi.mocked(getConfig).mockReset().mockRejectedValue(new Error('no config in this test'))
  vi.mocked(storeSecret)
    .mockReset()
    .mockImplementation((_client, payload, lifetime) => {
      const id = 'id' + server.size + 'AAAAAAAAAAAAAAAAAAA'
      server.set(id, payload)
      received.push(encodeBase64(payload) + ' ' + String(lifetime))
      return Promise.resolve({ id, expiresAt: new Date('2030-01-01T00:00:00Z') })
    })
  vi.mocked(openSecret)
    .mockReset()
    .mockImplementation((_client, id) => {
      opens++
      const payload = server.get(id)
      // Read and delete in one step, like the server's GETDEL.
      server.delete(id)
      return payload ? Promise.resolve(payload) : Promise.reject(notFound())
    })
})

async function share(text: string, passphrase = ''): Promise<string> {
  const { unmount } = render(ShareSecret)
  await userEvent.type(screen.getByPlaceholderText('Type the secret here'), text)
  if (passphrase) await userEvent.type(screen.getByLabelText('Passphrase (optional)'), passphrase)
  await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
  const input = await screen.findByLabelText('Secret link')
  const url = (input as HTMLInputElement).value
  unmount()
  return url
}

function openLink(url: string) {
  const u = new URL(url)
  window.history.pushState({}, '', u.pathname + u.hash)
  const id = decodeURIComponent(u.pathname.split('/')[2])
  return render(RevealSecretView, { props: { id } })
}

describe('share and reveal', () => {
  it('round trips a text and the server never sees the key or the text', async () => {
    const url = await share('correct horse battery staple')
    const key = new URL(url).hash.slice(1)
    expect(url).toMatch(/\/s\/id0[A-Za-z0-9]+#[A-Za-z0-9_-]{43}$/)

    expect(received).toHaveLength(1)
    const sent = received[0] + ' ' + [...server.keys()].join(' ')
    expect(sent).not.toContain(key)
    expect(atob(received[0].split(' ')[0])).not.toContain('correct horse')

    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByTestId('revealed-text')).toHaveTextContent(
      'correct horse battery staple',
    )
    expect(server.size).toBe(0)
    // The spent link's key is gone from the address bar.
    expect(window.location.hash).toBe('')
  })

  it('does not ask the server until the reveal button is clicked', async () => {
    const url = await share('hello')
    openLink(url)

    expect(await screen.findByRole('button', { name: 'Reveal the secret' })).toBeVisible()
    expect(opens).toBe(0)
    expect(server.size).toBe(1)
  })

  it('opens a link exactly once', async () => {
    const url = await share('once')
    const first = openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    await screen.findByTestId('revealed-text')
    first.unmount()

    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByText('This secret is not available')).toBeVisible()
    expect(screen.queryByTestId('revealed-text')).not.toBeInTheDocument()
  })

  it('refuses a link with no key or a mangled key without spending the secret', async () => {
    const url = await share('keep me')
    const id = new URL(url).pathname.split('/')[2]

    for (const hash of ['', '#', '#short', '#' + 'A'.repeat(44), '#' + 'A'.repeat(42) + '!']) {
      window.history.pushState({}, '', '/s/' + id + hash)
      const view = render(RevealSecretView, { props: { id } })
      expect(await screen.findByText('This link could not be opened')).toBeVisible()
      expect(screen.queryByRole('button', { name: 'Reveal the secret' })).not.toBeInTheDocument()
      view.unmount()
    }
    expect(opens).toBe(0)
    expect(server.size).toBe(1)
  })

  it('reports a wrong key as damaged, after the secret is already gone', async () => {
    const url = await share('secret')
    const u = new URL(url)
    const wrong = u.origin + u.pathname + '#' + 'A'.repeat(43)
    openLink(wrong)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))

    expect(await screen.findByText('The secret could not be decrypted')).toBeVisible()
    expect(screen.queryByTestId('revealed-text')).not.toBeInTheDocument()
  })

  it('needs the passphrase, keeps the payload for a retry, then reveals', async () => {
    const url = await share('guarded', 'open sesame')
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))

    const field = await screen.findByLabelText('Passphrase')
    await userEvent.type(field, 'wrong')
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    expect(
      await screen.findByText('This passphrase does not open the secret. Try again.'),
    ).toBeVisible()
    expect(screen.queryByTestId('revealed-text')).not.toBeInTheDocument()

    await userEvent.clear(field)
    await userEvent.type(field, 'open sesame')
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    expect(await screen.findByTestId('revealed-text')).toHaveTextContent('guarded')
    // The retry never went back to the server.
    expect(opens).toBe(1)
  })

  it('shows a transport failure without claiming the secret is gone', async () => {
    const url = await share('x')
    vi.mocked(openSecret).mockRejectedValueOnce(
      new ApiError({ code: 'network', message: 'offline', status: 0 }),
    )
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))

    expect(await screen.findByText('Could not reach the server')).toBeVisible()
  })

  it('round trips a file as a neutral download, never rendered', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:test')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }))

    const { unmount } = render(ShareSecret)
    const file = new File([new Uint8Array([1, 2, 3])], '../evil/<b>name.txt', { type: 'text/html' })
    await userEvent.upload(document.querySelector('input[type=file]') as HTMLInputElement, file)
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    const url = (await screen.findByLabelText<HTMLInputElement>('Secret link')).value
    unmount()

    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    const link = await screen.findByTestId('revealed-file')
    expect(link).toHaveAttribute('download', '.._evil_<b>name.txt')
    expect(link.getAttribute('download')).not.toMatch(/[\\/]/)
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(blob.type).toBe('application/octet-stream')
    vi.unstubAllGlobals()
  })

  it('clears the form once the link exists and renders text as text', async () => {
    const url = await share('<img src=x onerror=alert(1)>')
    expect(screen.queryByPlaceholderText('Type the secret here')).not.toBeInTheDocument()
    const view = openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    const shown = await screen.findByTestId('revealed-text')
    expect(shown.textContent).toBe('<img src=x onerror=alert(1)>')
    expect(view.container.querySelector('img')).toBeNull()
  })

  it('sends the chosen lifetime and refuses an empty secret', async () => {
    vi.mocked(getConfig).mockResolvedValue({
      maxCiphertextBytes: 1024,
      lifetime: { minSeconds: 60, maxSeconds: 604800, defaultSeconds: 86400 },
    })
    render(ShareSecret)
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    expect(await screen.findByText('Enter a secret text or attach a file first.')).toBeVisible()
    expect(storeSecret).not.toHaveBeenCalled()

    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    await waitFor(() => expect(getConfig).toHaveBeenCalled())
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    await screen.findByLabelText('Secret link')
    expect(received[0].endsWith(' 86400')).toBe(true)
  })

  it('refuses a secret above the server limit before sending it', async () => {
    vi.mocked(getConfig).mockResolvedValue({
      maxCiphertextBytes: 100,
      lifetime: { minSeconds: 60, maxSeconds: 604800, defaultSeconds: 86400 },
    })
    render(ShareSecret)
    await waitFor(() => expect(getConfig).toHaveBeenCalled())
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    // Let the config land before the click.
    await new Promise((r) => setTimeout(r, 0))
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))

    expect(await screen.findByText(/too large/)).toBeVisible()
    expect(storeSecret).not.toHaveBeenCalled()
  })

  it('shows a refusal from the server as a message, not a link', async () => {
    vi.mocked(storeSecret).mockRejectedValueOnce(
      new ApiError({ code: 'too_many_requests', message: 'slow down', status: 429 }),
    )
    render(ShareSecret)
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))

    expect(await screen.findByText(/Too many requests/)).toBeVisible()
    expect(screen.queryByTestId('secret-link')).not.toBeInTheDocument()
  })
})
