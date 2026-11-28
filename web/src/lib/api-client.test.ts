// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { isApiError } from '@ostendorf-cloud/govue'
import { describe, expect, it, vi } from 'vitest'

import { createHeadClient } from './api-client'
import { checkSecret } from './secrets-api'

describe('createHeadClient', () => {
  it('sends every request as HEAD with no body, whatever the call was', async () => {
    const fetch = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })))
    const client = createHeadClient(fetch)

    await checkSecret(client, 'AAAAAAAAAAAAAAAAAAAAAA')

    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/v1/secrets/AAAAAAAAAAAAAAAAAAAAAA')
    expect(init.method).toBe('HEAD')
    expect(init.body).toBeUndefined()
  })

  it('raises the one refusal as a 404 api error', async () => {
    const client = createHeadClient(() => Promise.resolve(new Response(null, { status: 404 })))

    const err = await checkSecret(client, 'AAAAAAAAAAAAAAAAAAAAAA').catch((e: unknown) => e)

    expect(isApiError(err)).toBe(true)
    expect(isApiError(err) && err.status).toBe(404)
  })

  it('raises a transport failure as an api error that is not a 404', async () => {
    const client = createHeadClient(() => Promise.reject(new TypeError('Failed to fetch')))

    const err = await checkSecret(client, 'AAAAAAAAAAAAAAAAAAAAAA').catch((e: unknown) => e)

    expect(isApiError(err)).toBe(true)
    expect(isApiError(err) && err.status).not.toBe(404)
  })
})
