// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from '@testing-library/vue'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import CreateRequestLink from './CreateRequestLink.vue'

vi.mock('../lib/request-link-api', () => ({
  createRequestLink: vi.fn(),
}))
vi.mock('../lib/request-link-keys', () => ({
  saveOwnerKey: vi.fn().mockResolvedValue(undefined),
  requestPersistentStorage: vi.fn().mockResolvedValue(true),
}))

import { createRequestLink } from '../lib/request-link-api'
import { saveOwnerKey } from '../lib/request-link-keys'

describe('CreateRequestLink', () => {
  beforeEach(() => {
    vi.mocked(createRequestLink).mockReset()
    vi.mocked(saveOwnerKey).mockClear()
  })

  it('states the loss of the key before anything is created', () => {
    render(CreateRequestLink)

    expect(screen.getByTestId('loss-notice').textContent).toMatch(/permanently/i)
    expect(screen.queryByTestId('created-link')).not.toBeInTheDocument()
  })

  it('shows the created link and its limits once creation succeeds', async () => {
    vi.mocked(createRequestLink).mockResolvedValue({
      id: 'abc123',
      expiresAt: new Date('2026-02-01T00:00:00Z'),
      maxSubmissionBytes: 1048576,
      maxConcurrentSubmissions: 50,
    })

    render(CreateRequestLink)
    await userEvent.click(screen.getByRole('button', { name: 'Create a request link' }))

    await waitFor(() => expect(screen.getByTestId('created-link')).toBeVisible())
    expect(screen.getByDisplayValue(/\/r\/abc123#/)).toBeVisible()
    expect(saveOwnerKey).toHaveBeenCalledTimes(1)
    expect(saveOwnerKey).toHaveBeenCalledWith('abc123', expect.anything())
  })

  it('shows an error instead of a link when the server refuses the request', async () => {
    vi.mocked(createRequestLink).mockRejectedValue(new Error('server exploded'))

    render(CreateRequestLink)
    await userEvent.click(screen.getByRole('button', { name: 'Create a request link' }))

    await waitFor(() =>
      expect(screen.getByText('Could not create a request link. Please try again.')).toBeVisible(),
    )
    expect(screen.queryByTestId('created-link')).not.toBeInTheDocument()
  })
})
