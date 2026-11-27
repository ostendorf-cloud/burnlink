// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from '@testing-library/vue'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { sealSubmission, generateOwnerKeyPair } from '../lib/request-link-crypto'
import { encodeOwnerPublicKeyFragment } from '../lib/request-link'
import RequestLinkView from './RequestLinkView.vue'

vi.mock('../lib/request-link-api', () => ({
  submitToRequestLink: vi.fn().mockResolvedValue(undefined),
  openRequestLink: vi.fn(),
  getRequestLinkInfo: vi.fn(),
}))
vi.mock('../lib/request-link-keys', () => ({
  hasOwnerKey: vi.fn(),
  loadOwnerKey: vi.fn(),
}))
vi.mock('../lib/request-link-submissions', () => ({
  loadSubmissions: vi.fn(),
  appendSubmissions: vi.fn(),
}))

import { getRequestLinkInfo, openRequestLink, submitToRequestLink } from '../lib/request-link-api'
import { hasOwnerKey, loadOwnerKey } from '../lib/request-link-keys'
import { appendSubmissions, loadSubmissions } from '../lib/request-link-submissions'

function setLocation(hash: string) {
  window.location.hash = hash
}

describe('RequestLinkView', () => {
  beforeEach(() => {
    vi.mocked(hasOwnerKey).mockReset().mockResolvedValue(false)
    vi.mocked(loadOwnerKey).mockReset()
    vi.mocked(openRequestLink).mockReset()
    vi.mocked(getRequestLinkInfo)
      .mockReset()
      .mockResolvedValue({ expiresAt: new Date(0), maxSubmissionBytes: 2 << 20 })
    vi.mocked(submitToRequestLink).mockReset().mockResolvedValue(undefined)
    vi.mocked(loadSubmissions).mockReset().mockResolvedValue([])
    vi.mocked(appendSubmissions)
      .mockReset()
      .mockImplementation((_id, newSubmissions) => Promise.resolve(newSubmissions))
  })

  afterEach(() => {
    setLocation('')
  })

  it('renders inside the main landmark the skip link points to, while loading and on error', async () => {
    setLocation('')
    const { container } = render(RequestLinkView, { props: { id: 'abc' } })

    // Loading: the mount check has not settled yet.
    expect(container.querySelector('main#main')).not.toBeNull()

    await waitFor(() => expect(screen.getByText(/missing its key/i)).toBeVisible())
    expect(screen.getAllByRole('main')).toHaveLength(1)
    expect(container.querySelector('main#main')).not.toBeNull()
  })

  it('refuses a link with no fragment instead of asking the server for the key', async () => {
    setLocation('')
    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText(/missing its key/i)).toBeVisible())
  })

  it('shows the submit form once the fragment carries a usable public key', async () => {
    const owner = await generateOwnerKeyPair()
    setLocation(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByRole('button', { name: 'Send' })).toBeVisible())
  })

  it('shows the size limit to a submitter before a file is chosen', async () => {
    const owner = await generateOwnerKeyPair()
    setLocation(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByTestId('size-limit')).toHaveTextContent('at most 2 MiB'))
    expect(getRequestLinkInfo).toHaveBeenCalledWith(expect.anything(), 'abc')
  })

  it('still shows the submit form when the size limit cannot be read', async () => {
    const owner = await generateOwnerKeyPair()
    setLocation(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))
    vi.mocked(getRequestLinkInfo).mockRejectedValue(new Error('network error'))

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByRole('button', { name: 'Send' })).toBeVisible())
    expect(screen.queryByTestId('size-limit')).not.toBeInTheDocument()
  })

  it('offers to save a received file to disk', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    vi.mocked(loadSubmissions).mockResolvedValue([
      {
        type: 'file',
        name: '../report.pdf',
        mime: 'application/pdf',
        data: new Uint8Array([1, 2]),
      },
    ])
    vi.mocked(openRequestLink).mockResolvedValue([])
    const createObjectURL = vi.fn().mockReturnValue('blob:test')
    const revokeObjectURL = vi.fn()
    Object.assign(URL, { createObjectURL, revokeObjectURL })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    try {
      render(RequestLinkView, { props: { id: 'abc' } })
      const save = await screen.findByRole('button', { name: 'Save .._report.pdf' })
      await userEvent.click(save)

      expect(createObjectURL).toHaveBeenCalledTimes(1)
      const blob = createObjectURL.mock.calls[0][0] as Blob
      expect(blob.type).toBe('application/octet-stream')
      expect(click).toHaveBeenCalledTimes(1)
      expect(click.mock.contexts[0]).toHaveProperty('download', '.._report.pdf')
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:test')
    } finally {
      click.mockRestore()
      Reflect.deleteProperty(URL, 'createObjectURL')
      Reflect.deleteProperty(URL, 'revokeObjectURL')
    }
  })

  it('seals and submits the typed text, then shows it was sent', async () => {
    const owner = await generateOwnerKeyPair()
    setLocation(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))

    render(RequestLinkView, { props: { id: 'abc' } })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Send' })).toBeVisible())

    await userEvent.type(screen.getByLabelText('Secret text'), 'a secret for the owner')
    await userEvent.click(screen.getByRole('button', { name: 'Send' }))

    await waitFor(() => expect(screen.getByText('Sent')).toBeVisible())
    expect(submitToRequestLink).toHaveBeenCalledTimes(1)
    const [, id, payload] = vi.mocked(submitToRequestLink).mock.calls[0]
    expect(id).toBe('abc')
    expect(payload).toBeInstanceOf(Uint8Array)
  })

  it('opens every submission waiting for the owner and shows its text', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    const sealed = await sealSubmission({ type: 'text', text: 'hello owner' }, owner.publicKeyRaw)
    vi.mocked(openRequestLink).mockResolvedValue([sealed])

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText('hello owner')).toBeVisible())
  })

  it('shows an empty state when the owner has nothing waiting', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    vi.mocked(openRequestLink).mockResolvedValue([])

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText('Nothing waiting')).toBeVisible())
    expect(screen.getByText(/No submission has arrived yet/)).toBeVisible()
  })

  it('saves a newly opened submission before showing it', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    const sealed = await sealSubmission({ type: 'text', text: 'hello owner' }, owner.publicKeyRaw)
    vi.mocked(openRequestLink).mockResolvedValue([sealed])

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText('hello owner')).toBeVisible())
    expect(appendSubmissions).toHaveBeenCalledTimes(1)
    const [id, saved] = vi.mocked(appendSubmissions).mock.calls[0]
    expect(id).toBe('abc')
    expect(saved).toEqual([{ type: 'text', text: 'hello owner' }])
  })

  it('shows a submission saved on an earlier visit without calling the server again first', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    vi.mocked(loadSubmissions).mockResolvedValue([{ type: 'text', text: 'saved from before' }])
    vi.mocked(openRequestLink).mockResolvedValue([])

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText('saved from before')).toBeVisible())
  })

  it('reports a newly opened submission as lost, without hiding what was already saved, when it cannot be saved', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    vi.mocked(loadSubmissions).mockResolvedValue([{ type: 'text', text: 'saved from before' }])
    const sealed = await sealSubmission({ type: 'text', text: 'hello owner' }, owner.publicKeyRaw)
    vi.mocked(openRequestLink).mockResolvedValue([sealed])
    vi.mocked(appendSubmissions).mockRejectedValue(new Error('quota exceeded'))

    render(RequestLinkView, { props: { id: 'abc' } })

    await waitFor(() => expect(screen.getByText(/cannot be recovered/i)).toBeVisible())
    expect(screen.getByText('saved from before')).toBeVisible()
    expect(screen.queryByText('hello owner')).not.toBeInTheDocument()
  })

  it('reports every payload removed from the server as lost, including one that failed to decrypt', async () => {
    const owner = await generateOwnerKeyPair()
    const foreignOwner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    const forOwner = await sealSubmission(
      { type: 'text', text: 'for the real owner' },
      owner.publicKeyRaw,
    )
    const forSomeoneElse = await sealSubmission(
      { type: 'text', text: 'sealed to a different owner' },
      foreignOwner.publicKeyRaw,
    )
    vi.mocked(openRequestLink).mockResolvedValue([forOwner, forSomeoneElse])
    vi.mocked(appendSubmissions).mockRejectedValue(new Error('quota exceeded'))

    render(RequestLinkView, { props: { id: 'abc' } })

    // Both payloads were already removed from the server by the one open()
    // call above; only one of them decrypted. The count must name both, or
    // it understates the loss by exactly the one this browser could never
    // have read in the first place.
    await waitFor(() => expect(screen.getByText(/^2 submissions arrived/)).toBeVisible())
  })

  it('tells the owner nothing was lost when checking for new submissions fails over the network', async () => {
    const owner = await generateOwnerKeyPair()
    vi.mocked(hasOwnerKey).mockResolvedValue(true)
    vi.mocked(loadOwnerKey).mockResolvedValue(owner)
    vi.mocked(loadSubmissions).mockResolvedValue([{ type: 'text', text: 'saved from before' }])
    vi.mocked(openRequestLink).mockRejectedValue(new Error('network error'))

    render(RequestLinkView, { props: { id: 'abc' } })

    // This browser's own durable copy loaded and rendered; the server round
    // trip is what failed, and nothing was ever removed from the server.
    // The owner must see a message that says so, not the "could not be
    // saved" wording a real loss gets.
    await waitFor(() =>
      expect(screen.getByText('Could not check for new submissions')).toBeVisible(),
    )
    expect(screen.getByText('saved from before')).toBeVisible()
    expect(screen.queryByText('Some submissions could not be saved')).not.toBeInTheDocument()
  })

  it('tells a submitter plainly when this browser cannot submit at all, instead of a generic failure', async () => {
    const owner = await generateOwnerKeyPair()
    setLocation(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))

    const subtle = globalThis.crypto.subtle
    const originalGenerateKey = subtle.generateKey.bind(subtle)
    const originalImportKey = subtle.importKey.bind(subtle)
    subtle.generateKey = (() => {
      throw new DOMException('Unrecognized algorithm name', 'NotSupportedError')
    }) as typeof subtle.generateKey
    subtle.importKey = (() => {
      throw new DOMException('Unrecognized algorithm name', 'NotSupportedError')
    }) as typeof subtle.importKey

    try {
      render(RequestLinkView, { props: { id: 'abc' } })
      await waitFor(() =>
        expect(screen.getByText(/cannot create or open a request link/i)).toBeVisible(),
      )
    } finally {
      subtle.generateKey = originalGenerateKey
      subtle.importKey = originalImportKey
    }
  })
})
