// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest'
import type { ApiClient } from '@ostendorf-cloud/govue'

import { decodeBase64, generateLinkKey } from './crypto'
import { MissingKeyError, linkKeyFromFragment, secretURL } from './secret-link'
import { openSecret, storeSecret } from './secrets-api'

describe('secret link', () => {
  it('builds /s/<id>#<key> and reads the key back', () => {
    const key = generateLinkKey()
    const url = new URL(secretURL('https://burnlink.test', 'abc', key))

    expect(url.pathname).toBe('/s/abc')
    expect(linkKeyFromFragment(url.hash.slice(1))).toEqual(key)
  })

  it.each(['', 'short', 'A'.repeat(44), '!' + 'A'.repeat(42), 'A'.repeat(42) + 'B'])(
    'refuses the fragment %j',
    (fragment) => {
      expect(() => linkKeyFromFragment(fragment)).toThrow(MissingKeyError)
    },
  )
})

describe('secrets api', () => {
  it('posts only the ciphertext and the lifetime, base64 encoded', async () => {
    const post = vi.fn().mockResolvedValue({ id: 'x', expiresAt: '2030-01-01T00:00:00Z' })
    const client = { post } as unknown as ApiClient

    await storeSecret(client, new Uint8Array([1, 2, 3]), 60)

    expect(post).toHaveBeenCalledWith('/secrets', { ciphertext: 'AQID', lifetimeSeconds: 60 })
  })

  it('leaves the lifetime out when none is chosen', async () => {
    const post = vi.fn().mockResolvedValue({ id: 'x', expiresAt: '2030-01-01T00:00:00Z' })

    await storeSecret({ post } as unknown as ApiClient, new Uint8Array([1]))

    expect(post.mock.calls[0][1]).toEqual({ ciphertext: 'AQ==' })
  })

  it('opens with an escaped id and decodes the ciphertext', async () => {
    const post = vi.fn().mockResolvedValue({ ciphertext: 'AQID' })

    const bytes = await openSecret({ post } as unknown as ApiClient, 'a/b')

    expect(post).toHaveBeenCalledWith('/secrets/a%2Fb/open', {})
    expect(bytes).toEqual(decodeBase64('AQID'))
  })
})
