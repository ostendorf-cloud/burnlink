// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The share and the reveal view together over an in-memory stand in for the
// server: real crypto, real components, only the network call replaced.

import { cleanup, render, screen, waitFor } from '@testing-library/vue'
import userEvent from '@testing-library/user-event'
import { ApiError } from '@ostendorf-cloud/govue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { decryptSecret, encodeBase64, type Bytes, type Content } from '../lib/crypto'
import type * as CryptoModule from '../lib/crypto'
import RevealSecretView from './RevealSecretView.vue'
import ShareSecret from './ShareSecret.vue'

vi.mock('../lib/secrets-api', () => ({
  getConfig: vi.fn(),
  storeSecret: vi.fn(),
  openSecret: vi.fn(),
}))

// The real decryption, wrapped in a spy: the tests read the buffers the view
// handed to it to see whether the view zeroed them afterwards.
vi.mock('../lib/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof CryptoModule>()
  return { ...actual, decryptSecret: vi.fn(actual.decryptSecret) }
})

import { getConfig, openSecret, storeSecret } from '../lib/secrets-api'

const isZero = (b: Bytes) => b.every((x) => x === 0)

// What the view passed to the last decryptSecret call: the payload and the key.
function lastDecryptArgs(): { payload: Bytes; key: Bytes } {
  const calls = vi.mocked(decryptSecret).mock.calls
  const [payload, key] = calls[calls.length - 1]
  return { payload, key }
}

// jsdom has no object URLs. The spies are removed again after each test.
function stubObjectURLs() {
  const createObjectURL = vi.fn().mockReturnValue('blob:test')
  const revokeObjectURL = vi.fn()
  Object.assign(URL, { createObjectURL, revokeObjectURL })
  return { createObjectURL, revokeObjectURL }
}

afterEach(() => {
  Reflect.deleteProperty(URL, 'createObjectURL')
  Reflect.deleteProperty(URL, 'revokeObjectURL')
})

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
  vi.mocked(decryptSecret).mockClear()
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

async function shareFile(file: File): Promise<string> {
  const { unmount } = render(ShareSecret)
  await userEvent.upload(screen.getByLabelText('Or attach a file instead'), file)
  await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
  const url = (await screen.findByLabelText<HTMLInputElement>('Secret link')).value
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
    expect(await screen.findByText('The passphrase or the link is wrong.')).toBeVisible()
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
    const { createObjectURL } = stubObjectURLs()
    const file = new File([new Uint8Array([1, 2, 3])], '../evil/<b>name.txt', { type: 'text/html' })
    const url = await shareFile(file)

    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    const link = await screen.findByTestId('revealed-file')
    expect(link).toHaveAttribute('download', '.._evil_<b>name.txt')
    expect(link.getAttribute('download')).not.toMatch(/[\\/]/)
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(blob.type).toBe('application/octet-stream')
  })

  it('strips bidirectional controls from a file name and caps its length', async () => {
    stubObjectURLs()
    const bidi = '‪‫‬‭‮⁦⁧⁨⁩'
    const url = await shareFile(new File([new Uint8Array([1])], `evil${bidi}txt.exe`))
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByTestId('revealed-file')).toHaveAttribute('download', 'eviltxt.exe')
    cleanup()

    window.history.pushState({}, '', '/')
    const long = 'a'.repeat(300) + '.txt'
    const url2 = await shareFile(new File([new Uint8Array([1])], long))
    openLink(url2)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    const name = (await screen.findByTestId('revealed-file')).getAttribute('download') ?? ''
    expect(name).toHaveLength(120)
    expect(name).toBe('a'.repeat(120))
  })

  it('drops the key and the payload once the secret is shown', async () => {
    const url = await share('wipe me')
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByTestId('revealed-text')).toHaveTextContent('wipe me')

    const { payload, key } = lastDecryptArgs()
    expect(key).toHaveLength(32)
    expect(isZero(key)).toBe(true)
    expect(isZero(payload)).toBe(true)
  })

  it('drops the secret when the view is unmounted', async () => {
    const { revokeObjectURL } = stubObjectURLs()
    const url = await shareFile(new File([new Uint8Array([7, 7, 7])], 'a.bin'))
    const view = openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    await screen.findByTestId('revealed-file')
    const content = (await vi.mocked(decryptSecret).mock.results[0].value) as Content
    if (content.type !== 'file') throw new Error('expected a file')
    expect(isZero(content.data)).toBe(false)

    view.unmount()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:test')
    expect(isZero(content.data)).toBe(true)
  })

  it('drops the secret on pagehide, also for a page that goes into the bfcache', async () => {
    const { revokeObjectURL } = stubObjectURLs()
    const url = await shareFile(new File([new Uint8Array([7, 7, 7])], 'a.bin'))
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    await screen.findByTestId('revealed-file')
    const content = (await vi.mocked(decryptSecret).mock.results[0].value) as Content
    if (content.type !== 'file') throw new Error('expected a file')

    window.dispatchEvent(Object.assign(new Event('pagehide'), { persisted: true }))

    expect(await screen.findByText('This page was left')).toBeVisible()
    expect(screen.queryByTestId('revealed-file')).not.toBeInTheDocument()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:test')
    expect(isZero(content.data)).toBe(true)
  })

  it('drops the text on pagehide and the buffers held for a passphrase retry', async () => {
    const url = await share('hidden text', 'pw')
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    await screen.findByLabelText('Passphrase')
    const { payload, key } = lastDecryptArgs()
    expect(isZero(key)).toBe(false)
    expect(isZero(payload)).toBe(false)

    window.dispatchEvent(new Event('pagehide'))

    expect(await screen.findByText('This page was left')).toBeVisible()
    expect(isZero(key)).toBe(true)
    expect(isZero(payload)).toBe(true)
    expect(screen.queryByLabelText('Passphrase')).not.toBeInTheDocument()
  })

  it('removes a shown text from the page on pagehide', async () => {
    const url = await share('shown text')
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByTestId('revealed-text')).toBeVisible()

    window.dispatchEvent(new Event('pagehide'))

    expect(await screen.findByText('This page was left')).toBeVisible()
    expect(document.body.textContent).not.toContain('shown text')
  })

  it('wipes a page restored from the bfcache and ignores a normal pageshow', async () => {
    const url = await share('restored')
    openLink(url)
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))
    expect(await screen.findByTestId('revealed-text')).toBeVisible()

    window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: false }))
    expect(screen.getByTestId('revealed-text')).toBeVisible()
    window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }))
    expect(await screen.findByText('This page was left')).toBeVisible()
    expect(screen.queryByTestId('revealed-text')).not.toBeInTheDocument()
  })

  it('says the passphrase or the link is wrong for a damaged key too', async () => {
    const url = await share('guarded', 'open sesame')
    const u = new URL(url)
    openLink(u.origin + u.pathname + '#' + 'A'.repeat(43))
    await userEvent.click(screen.getByRole('button', { name: 'Reveal the secret' }))

    await userEvent.type(await screen.findByLabelText('Passphrase'), 'open sesame')
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    expect(await screen.findByText('The passphrase or the link is wrong.')).toBeVisible()
    expect(screen.queryByTestId('revealed-text')).not.toBeInTheDocument()
  })

  it('ignores a key in the query string', async () => {
    const url = await share('only the fragment counts')
    const u = new URL(url)
    const key = u.hash.slice(1)
    window.history.pushState({}, '', u.pathname + '?key=' + key + '&k=' + key)
    render(RevealSecretView, { props: { id: u.pathname.split('/')[2] } })

    expect(await screen.findByText('This link could not be opened')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Reveal the secret' })).not.toBeInTheDocument()
    expect(opens).toBe(0)
    expect(server.size).toBe(1)
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

  it('offers only lifetimes within the server limits and sends a non default choice', async () => {
    vi.mocked(getConfig).mockResolvedValue({
      maxCiphertextBytes: 4096,
      lifetime: { minSeconds: 3600, maxSeconds: 604800, defaultSeconds: 86400 },
    })
    // Reka's select needs these pointer APIs, which jsdom lacks.
    Object.assign(HTMLElement.prototype, {
      hasPointerCapture: () => false,
      setPointerCapture: () => undefined,
      releasePointerCapture: () => undefined,
      scrollIntoView: () => undefined,
    })
    render(ShareSecret)
    const select = await screen.findByRole('combobox', { name: 'Expires after' })
    expect(select).toHaveTextContent('24 hours')
    await userEvent.click(select)
    const labels = (await screen.findAllByRole('option')).map((o) => o.textContent?.trim())
    // 5 minutes is below the minimum, 30 days above the maximum.
    expect(labels).toEqual(['1 hour', '24 hours', '7 days'])

    await userEvent.click(screen.getByRole('option', { name: '7 days' }))
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    await screen.findByLabelText('Secret link')
    expect(received[0].endsWith(' 604800')).toBe(true)
  })

  it('submits with Enter in the passphrase field and labels the file input', async () => {
    render(ShareSecret)
    expect(screen.getByLabelText('Or attach a file instead')).toHaveAttribute('type', 'file')
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'enter')
    await userEvent.type(screen.getByLabelText('Passphrase (optional)'), 'pw{Enter}')
    expect(await screen.findByLabelText('Secret link')).toBeVisible()
    expect(received).toHaveLength(1)
  })

  it('resets the file input once the link exists', async () => {
    render(ShareSecret)
    const input = screen.getByLabelText<HTMLInputElement>('Or attach a file instead')
    await userEvent.upload(input, new File([new Uint8Array([1])], 'a.bin'))
    expect(input.files).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    await screen.findByLabelText('Secret link')
    expect(input.files).toHaveLength(0)
    expect(input.value).toBe('')
  })

  it('refuses a file above the limit before reading it', async () => {
    vi.mocked(getConfig).mockResolvedValue({
      maxCiphertextBytes: 10,
      lifetime: { minSeconds: 60, maxSeconds: 604800, defaultSeconds: 86400 },
    })
    render(ShareSecret)
    await waitFor(() => expect(getConfig).toHaveBeenCalled())
    await new Promise((r) => setTimeout(r, 0))
    const file = new File([new Uint8Array(50)], 'big.bin')
    const read = vi.spyOn(file, 'arrayBuffer')
    await userEvent.upload(screen.getByLabelText('Or attach a file instead'), file)
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))

    expect(await screen.findByText(/too large/)).toBeVisible()
    expect(read).not.toHaveBeenCalled()
    expect(storeSecret).not.toHaveBeenCalled()
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

  it('says where the address is entered that the server stores and learns it', () => {
    render(ShareSecret)
    const field = screen.getByLabelText(/Notify me when it is opened/)
    expect(field).toHaveAttribute('type', 'url')
    // The notice is the field's own description, so it is read with the field.
    const description = field.getAttribute('aria-describedby')
    expect(description).toBeTruthy()
    const text = description
      ?.split(' ')
      .map((id) => document.getElementById(id)?.textContent ?? '')
      .join(' ')
    expect(text).toMatch(/server stores this address/)
    expect(text).toMatch(/learns it/)
    expect(text).toMatch(/never the secret/)
    expect(text).toMatch(/not guaranteed/)
  })

  it('sends the webhook address only when one was typed, and forgets it afterwards', async () => {
    render(ShareSecret)
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    await userEvent.type(
      screen.getByLabelText(/Notify me when it is opened/),
      ' https://hooks.example.com/x ',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))
    await screen.findByLabelText('Secret link')

    expect(vi.mocked(storeSecret).mock.calls[0][3]).toBe('https://hooks.example.com/x')
    expect(screen.getByLabelText(/Notify me when it is opened/)).toHaveValue('')
    expect(screen.getByText(/call your webhook once/)).toBeVisible()
  })

  it('sends no webhook address by default', async () => {
    await share('hi')
    expect(vi.mocked(storeSecret).mock.calls[0][3]).toBe('')
  })

  it('explains a refused webhook address without repeating it', async () => {
    vi.mocked(storeSecret).mockRejectedValueOnce(
      new ApiError({ code: 'invalid_argument', message: 'bad', status: 400 }),
    )
    render(ShareSecret)
    await userEvent.type(screen.getByPlaceholderText('Type the secret here'), 'hi')
    await userEvent.type(screen.getByLabelText(/Notify me when it is opened/), 'http://10.0.0.1/x')
    await userEvent.click(screen.getByRole('button', { name: 'Create link' }))

    const message = await screen.findByText(/notification address was not accepted/)
    expect(message).toBeVisible()
    expect(message.textContent).not.toContain('10.0.0.1')
    expect(screen.queryByTestId('secret-link')).not.toBeInTheDocument()
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
