// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// apiClient is the one place this app's components reach the server
// through, govue's own createClient with every default: no session cookie
// and no CSRF token are in play yet, and the base path matches
// internal/webapp/requestlink's own routes under /api/v1. No key is ever
// sent. Two values derived from the owner's keypair are: ownerAuthHash, a
// SHA-256 digest, and ownerAuth, an HKDF output. Neither reveals a key, since
// both come from a one way function.
import { createClient, type ApiClient } from '@ostendorf-cloud/govue'

export const apiClient = createClient()

/**
 * createHeadClient returns a govue client whose every request goes out as
 * HEAD. govue's client has no HEAD method, and the existence check of a secret
 * (HEAD /api/v1/secrets/{id}) is the one call that needs it. The client still
 * brings its own timeout, error shape and base path. Only the verb differs,
 * so a caller sends it with `get` and a path, and never a body.
 */
export function createHeadClient(
  doFetch: typeof globalThis.fetch = (input, init) => globalThis.fetch(input, init),
): ApiClient {
  return createClient({
    fetch: (input, init) => doFetch(input, { ...init, method: 'HEAD' }),
  })
}

export const headClient = createHeadClient()
