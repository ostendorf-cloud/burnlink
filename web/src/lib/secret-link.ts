// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The one time secret's own URL: /s/<id>#<key>. The key travels only in the
// fragment, which a browser never sends to a server.

import { KEY_BYTES, decodeBase64url, encodeBase64url, type Bytes } from './crypto'

/** Thrown when a link has no usable key. Raised before the server is asked. */
export class MissingKeyError extends Error {
  constructor() {
    super(
      'this link is missing its key. Open the link exactly as it was shared, including everything after the #',
    )
    this.name = 'MissingKeyError'
  }
}

/** secretURL builds the link a sender shares. */
export function secretURL(origin: string, id: string, linkKey: Bytes): string {
  return `${origin}/s/${encodeURIComponent(id)}#${encodeBase64url(linkKey)}`
}

/**
 * linkKeyFromFragment reads the key out of a fragment (without the #). Anything
 * that is not exactly 32 bytes of canonical base64url is refused, so a mangled
 * link is told apart from a failed decryption without spending the secret.
 */
export function linkKeyFromFragment(fragment: string): Bytes {
  if (!fragment) throw new MissingKeyError()
  let key: Bytes
  try {
    key = decodeBase64url(fragment)
  } catch {
    throw new MissingKeyError()
  }
  if (key.length !== KEY_BYTES) throw new MissingKeyError()
  return key
}
