// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// WebCrypto, not jsdom: jsdom ships no SubtleCrypto, and
// importOwnerPublicKeyFromFragment needs it.
import { expect, test } from 'vitest'

import { generateOwnerKeyPair } from './request-link-crypto'
import {
  MissingFragmentError,
  decodeOwnerPublicKeyFragment,
  encodeOwnerPublicKeyFragment,
  importOwnerPublicKeyFromFragment,
  requestLinkURL,
} from './request-link'

test('a public key round trips through the fragment encoding', async () => {
  const owner = await generateOwnerKeyPair()
  const fragment = encodeOwnerPublicKeyFragment(owner.publicKeyRaw)
  expect(decodeOwnerPublicKeyFragment(fragment)).toEqual(owner.publicKeyRaw)
})

test('an empty fragment is refused instead of treated as a missing key', () => {
  expect(() => decodeOwnerPublicKeyFragment('')).toThrow(MissingFragmentError)
})

test('a fragment of the wrong length is refused the same way as a missing one', () => {
  expect(() => decodeOwnerPublicKeyFragment('AAAA')).toThrow(MissingFragmentError)
})

test('a fragment that is not base64url is refused the same way as a missing one', () => {
  expect(() => decodeOwnerPublicKeyFragment('not base64url!')).toThrow(MissingFragmentError)
})

test('importOwnerPublicKeyFromFragment returns a usable key and the raw bytes', async () => {
  const owner = await generateOwnerKeyPair()
  const fragment = encodeOwnerPublicKeyFragment(owner.publicKeyRaw)
  const { publicKey, publicKeyRaw } = await importOwnerPublicKeyFromFragment(fragment)
  expect(publicKeyRaw).toEqual(owner.publicKeyRaw)
  expect(publicKey.type).toBe('public')
})

test('importOwnerPublicKeyFromFragment refuses a missing fragment before touching Web Crypto', async () => {
  await expect(importOwnerPublicKeyFromFragment('')).rejects.toThrow(MissingFragmentError)
})

test('requestLinkURL carries the id in the path and the key only in the fragment', async () => {
  const owner = await generateOwnerKeyPair()
  const url = requestLinkURL('https://burnlink.de', 'abc 123', owner.publicKeyRaw)
  expect(url).toBe(
    `https://burnlink.de/r/abc%20123#${encodeOwnerPublicKeyFragment(owner.publicKeyRaw)}`,
  )
  expect(url.split('#')[0]).not.toContain(encodeOwnerPublicKeyFragment(owner.publicKeyRaw))
})
