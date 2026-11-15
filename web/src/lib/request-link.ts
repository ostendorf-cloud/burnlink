// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The request link's own URL: building the one a browser shares, and
// reading the owner's public key back out of it. docs/adr/0003 settles
// that the key travels only in the fragment, which a browser never sends
// to the server, and that a link without one is refused rather than
// falling back to anything; this is where that refusal lives.

import { OWNER_PUBLIC_KEY_BYTES, importPublicKey } from './request-link-crypto'
import { decodeBase64url, encodeBase64url, type Bytes } from './crypto'

/**
 * Thrown when a request link's fragment is missing. The page shows this
 * message instead of asking the server for the key: there is no endpoint
 * that would answer, and none is to be built.
 */
export class MissingFragmentError extends Error {
  constructor() {
    super(
      'this request link is missing its key. Open the link exactly as it was shared, including everything after the #',
    )
    this.name = 'MissingFragmentError'
  }
}

/** encodeOwnerPublicKeyFragment is what a request link's URL carries after its #. */
export function encodeOwnerPublicKeyFragment(publicKeyRaw: Bytes): string {
  return encodeBase64url(publicKeyRaw)
}

/**
 * decodeOwnerPublicKeyFragment reads the owner's public key back out of a
 * request link's fragment (the part of the URL after #, without the #
 * itself). An empty fragment is refused as MissingFragmentError, never
 * treated as "no key", so a caller cannot mistake it for a link that
 * simply has none.
 */
export function decodeOwnerPublicKeyFragment(fragment: string): Bytes {
  if (!fragment) {
    throw new MissingFragmentError()
  }
  // Anything that is not exactly 32 raw bytes of valid base64url is not a
  // key this flow can use, whatever the precise reason: a stray character,
  // a copy that dropped bytes, or a fragment from an unrelated link. All of
  // it is refused the same way a missing fragment is, not with
  // decodeBase64url's own lower level complaint.
  let raw: Bytes
  try {
    raw = decodeBase64url(fragment)
  } catch {
    throw new MissingFragmentError()
  }
  if (raw.length !== OWNER_PUBLIC_KEY_BYTES) {
    throw new MissingFragmentError()
  }
  return raw
}

/**
 * importOwnerPublicKeyFromFragment combines decodeOwnerPublicKeyFragment
 * with importing the result as a usable X25519 key, the shape a submit
 * view actually needs.
 */
export async function importOwnerPublicKeyFromFragment(fragment: string): Promise<{
  publicKey: CryptoKey
  publicKeyRaw: Bytes
}> {
  const publicKeyRaw = decodeOwnerPublicKeyFragment(fragment)
  return { publicKey: await importPublicKey(publicKeyRaw), publicKeyRaw }
}

/** requestLinkURL builds the link an owner shares, id and fragment together. */
export function requestLinkURL(origin: string, id: string, publicKeyRaw: Bytes): string {
  return `${origin}/r/${encodeURIComponent(id)}#${encodeOwnerPublicKeyFragment(publicKeyRaw)}`
}
