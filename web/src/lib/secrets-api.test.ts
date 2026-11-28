// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import type { ApiClient } from '@ostendorf-cloud/govue'
import { expect, test, vi } from 'vitest'

import { encodeBase64 } from './crypto'
import { storeSecret } from './secrets-api'

function fakeClient(): ApiClient {
  const post = vi.fn(() => Promise.resolve({ id: 'abc', expiresAt: '2026-02-01T00:00:00Z' }))
  return { get: vi.fn(), post, put: vi.fn(), patch: vi.fn(), del: vi.fn() } as unknown as ApiClient
}

const payload = new Uint8Array([1, 2, 3])

test('storeSecret sends no notifyUrl unless one was given', async () => {
  const client = fakeClient()

  await storeSecret(client, payload)
  await storeSecret(client, payload, 60)
  await storeSecret(client, payload, 60, '')

  expect(client.post).toHaveBeenNthCalledWith(1, '/secrets', { ciphertext: encodeBase64(payload) })
  expect(client.post).toHaveBeenNthCalledWith(2, '/secrets', {
    ciphertext: encodeBase64(payload),
    lifetimeSeconds: 60,
  })
  expect(client.post).toHaveBeenNthCalledWith(3, '/secrets', {
    ciphertext: encodeBase64(payload),
    lifetimeSeconds: 60,
  })
})

test('storeSecret sends the webhook address as notifyUrl', async () => {
  const client = fakeClient()

  const stored = await storeSecret(client, payload, undefined, 'https://hooks.example.com/x')

  expect(client.post).toHaveBeenCalledWith('/secrets', {
    ciphertext: encodeBase64(payload),
    notifyUrl: 'https://hooks.example.com/x',
  })
  expect(stored).toEqual({ id: 'abc', expiresAt: new Date('2026-02-01T00:00:00Z') })
})
