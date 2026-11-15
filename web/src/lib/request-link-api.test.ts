// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import type { ApiClient } from '@ostendorf-cloud/govue'
import { expect, test, vi } from 'vitest'

import { encodeBase64 } from './crypto'
import { createRequestLink, openRequestLink, submitToRequestLink } from './request-link-api'

function fakeClient(responses: Record<string, unknown>): ApiClient {
  const post = vi.fn((path: string) => Promise.resolve(responses[path]))
  return {
    get: vi.fn(),
    post,
    put: vi.fn(),
    patch: vi.fn(),
    del: vi.fn(),
  } as unknown as ApiClient
}

test('createRequestLink sends the owner auth hash as base64 and parses the response', async () => {
  const expiresAt = '2026-02-01T00:00:00Z'
  const client = fakeClient({
    '/request-links': {
      id: 'abc',
      expiresAt,
      maxSubmissionBytes: 1024,
      maxConcurrentSubmissions: 5,
    },
  })
  const hash = new Uint8Array(32).fill(7)

  const link = await createRequestLink(client, hash)

  expect(client.post).toHaveBeenCalledWith('/request-links', {
    ownerAuthHash: encodeBase64(hash),
  })
  expect(link).toEqual({
    id: 'abc',
    expiresAt: new Date(expiresAt),
    maxSubmissionBytes: 1024,
    maxConcurrentSubmissions: 5,
  })
})

test('submitToRequestLink posts the payload as base64 to the link-specific path', async () => {
  const client = fakeClient({ '/request-links/abc%20def/submissions': undefined })
  const payload = new Uint8Array([1, 2, 3])

  await submitToRequestLink(client, 'abc def', payload)

  expect(client.post).toHaveBeenCalledWith('/request-links/abc%20def/submissions', {
    payload: encodeBase64(payload),
  })
})

test('openRequestLink sends the owner auth and decodes every returned submission', async () => {
  const a = new Uint8Array([1, 2, 3])
  const b = new Uint8Array([4, 5, 6])
  const client = fakeClient({
    '/request-links/abc/open': { submissions: [encodeBase64(a), encodeBase64(b)] },
  })
  const ownerAuth = new Uint8Array(32).fill(9)

  const submissions = await openRequestLink(client, 'abc', ownerAuth)

  expect(client.post).toHaveBeenCalledWith('/request-links/abc/open', {
    ownerAuth: encodeBase64(ownerAuth),
  })
  expect(submissions).toEqual([a, b])
})

test('openRequestLink returns an empty list when nothing is waiting', async () => {
  const client = fakeClient({ '/request-links/abc/open': { submissions: [] } })
  expect(await openRequestLink(client, 'abc', new Uint8Array(32))).toEqual([])
})
