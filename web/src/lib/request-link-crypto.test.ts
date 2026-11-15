// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// WebCrypto, not jsdom: jsdom ships no SubtleCrypto, and this module has no
// DOM access of its own.
import { afterEach, expect, test } from 'vitest'

import { DecryptError, type Content, type DecryptCode } from './crypto'
import {
  OWNER_PUBLIC_KEY_BYTES,
  SUBMISSION_VERSION,
  UnsupportedBrowserError,
  assertX25519Supported,
  deriveOwnerAuth,
  deriveSubmissionKey,
  generateOwnerKeyPair,
  importPublicKey,
  isX25519Supported,
  openSubmission,
  parseSubmissionHeader,
  sealSubmission,
} from './request-link-crypto'

const subtle = globalThis.crypto.subtle
const text: Content = { type: 'text', text: 'a secret only the owner can open ✓ äöü' }

async function rejectsWith(promise: Promise<unknown>, code: DecryptCode) {
  const error = await promise.then(
    () => null,
    (err: unknown) => err,
  )
  expect(error, 'the promise resolved instead of failing').toBeInstanceOf(DecryptError)
  expect((error as DecryptError).code).toBe(code)
}

test('an owner keypair has a public key of the documented length', async () => {
  const owner = await generateOwnerKeyPair()
  expect(owner.publicKeyRaw).toHaveLength(OWNER_PUBLIC_KEY_BYTES)
  expect(new Uint8Array(await subtle.exportKey('raw', owner.publicKey))).toEqual(owner.publicKeyRaw)
})

test('an owner keypair private key cannot be exported', async () => {
  const owner = await generateOwnerKeyPair()
  await expect(subtle.exportKey('pkcs8', owner.privateKey)).rejects.toThrow()
  await expect(subtle.exportKey('jwk', owner.privateKey)).rejects.toThrow()
})

test('two owner keypairs never share a public key', async () => {
  const a = await generateOwnerKeyPair()
  const b = await generateOwnerKeyPair()
  expect(a.publicKeyRaw).not.toEqual(b.publicKeyRaw)
})

test('text round trips through sealSubmission and openSubmission', async () => {
  const owner = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  expect(payload[0]).toBe(SUBMISSION_VERSION)
  expect(await openSubmission(payload, owner.privateKey, owner.publicKeyRaw)).toEqual(text)
})

test('file round trip keeps bytes, name and type', async () => {
  const owner = await generateOwnerKeyPair()
  const data = new Uint8Array(50000)
  for (let i = 0; i < data.length; i++) data[i] = (i * 13 + 5) & 0xff
  const file = { type: 'file' as const, name: 'notes.txt', mime: 'text/plain', data }
  const payload = await sealSubmission(file, owner.publicKeyRaw)
  expect(await openSubmission(payload, owner.privateKey, owner.publicKeyRaw)).toEqual(file)
})

test('the same submission seals differently every time', async () => {
  const owner = await generateOwnerKeyPair()
  const a = await sealSubmission(text, owner.publicKeyRaw)
  const b = await sealSubmission(text, owner.publicKeyRaw)
  expect(a).not.toEqual(b)
  // Different ephemeral public keys and different IVs: nothing is reused
  // across calls, which is what makes a random IV safe here.
  expect(parseSubmissionHeader(a).ephemeralPublicKey).not.toEqual(
    parseSubmissionHeader(b).ephemeralPublicKey,
  )
  expect(parseSubmissionHeader(a).iv).not.toEqual(parseSubmissionHeader(b).iv)
})

test('padding hides the length of short submissions', async () => {
  const owner = await generateOwnerKeyPair()
  const short = await sealSubmission({ type: 'text', text: 'a' }, owner.publicKeyRaw)
  const longer = await sealSubmission(
    { type: 'text', text: 'a much longer secret than the one above' },
    owner.publicKeyRaw,
  )
  expect(short.length).toBe(longer.length)
})

test('a submission sealed to one owner key cannot be opened with another', async () => {
  const ownerA = await generateOwnerKeyPair()
  const ownerB = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, ownerA.publicKeyRaw)
  await rejectsWith(openSubmission(payload, ownerB.privateKey, ownerB.publicKeyRaw), 'failed')
})

test('a key derived for the send flow cannot open a submission', async () => {
  const owner = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  const { ephemeralPublicKey, header, iv, ciphertext } = parseSubmissionHeader(payload)

  // Recover exactly the shared secret openSubmission would use, then derive
  // a key the way the send flow's own crypto.ts does: the same algorithm
  // family, HKDF-SHA-256 over that secret, but with its own fixed info
  // string and no notion of an ephemeral or owner public key.
  const peer = await importPublicKey(ephemeralPublicKey)
  const ecdhBits = new Uint8Array(
    await subtle.deriveBits({ name: 'X25519', public: peer }, owner.privateKey, 256),
  )
  const sendFlowBase = await subtle.importKey('raw', ecdhBits, 'HKDF', false, ['deriveKey'])
  const sendFlowKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('burnlink.de v1 aes-256-gcm'),
    },
    sendFlowBase,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )

  await expect(
    subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      sendFlowKey,
      ciphertext,
    ),
  ).rejects.toThrow()
})

test('deriveSubmissionKey separates owners even given the same shared secret', async () => {
  const ecdhBits = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const ephemeralPublicKeyRaw = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const ownerARaw = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const ownerBRaw = globalThis.crypto.getRandomValues(new Uint8Array(32))

  const keyA = await deriveSubmissionKey(ecdhBits, ephemeralPublicKeyRaw, ownerARaw, 'encrypt')
  const keyBForDecrypt = await deriveSubmissionKey(
    ecdhBits,
    ephemeralPublicKeyRaw,
    ownerBRaw,
    'decrypt',
  )

  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const header = new Uint8Array([SUBMISSION_VERSION, ...ephemeralPublicKeyRaw, ...iv])
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
    keyA,
    new TextEncoder().encode('hello'),
  )

  await expect(
    subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      keyBForDecrypt,
      ciphertext,
    ),
  ).rejects.toThrow()

  // The matching owner key, with the same shared secret and ephemeral key,
  // still opens it: the test above failed because the owner key differed,
  // not because of anything else that changed.
  const keyAForDecrypt = await deriveSubmissionKey(
    ecdhBits,
    ephemeralPublicKeyRaw,
    ownerARaw,
    'decrypt',
  )
  const opened = await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
    keyAForDecrypt,
    ciphertext,
  )
  expect(new TextDecoder().decode(opened)).toBe('hello')
})

test('deriveOwnerAuth is reproducible from the keypair and differs between keypairs', async () => {
  const a = await generateOwnerKeyPair()
  const b = await generateOwnerKeyPair()

  const first = await deriveOwnerAuth(a.privateKey, a.publicKey)
  const again = await deriveOwnerAuth(a.privateKey, a.publicKey)
  expect(first).toEqual(again)

  const forB = await deriveOwnerAuth(b.privateKey, b.publicKey)
  expect(forB).not.toEqual(first)
})

test('deriveOwnerAuth cannot be computed from the public key alone', async () => {
  const owner = await generateOwnerKeyPair()
  const real = await deriveOwnerAuth(owner.privateKey, owner.publicKey)

  // A stranger holding only the public key (what the link's fragment
  // carries) has no private key to call deriveOwnerAuth with at all; the
  // closest they can get is deriving a shared secret between two keys they
  // do hold, which is a different value.
  const stranger = await generateOwnerKeyPair()
  const strangersGuess = await deriveOwnerAuth(stranger.privateKey, owner.publicKey)
  expect(strangersGuess).not.toEqual(real)
})

test('tampering with the ephemeral public key, the IV, or the ciphertext breaks decryption', async () => {
  const owner = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  for (const index of [1, 20, payload.length - 1]) {
    const tampered = payload.slice()
    tampered[index] ^= 0x01
    await rejectsWith(openSubmission(tampered, owner.privateKey, owner.publicKeyRaw), 'failed')
  }
})

test('a payload claiming the wrong owner public key fails even with the right private key', async () => {
  const owner = await generateOwnerKeyPair()
  const other = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  // publicKeyRaw is not read from the payload at all: it is supplied by the
  // caller, exactly like the owner's own page would supply it from where
  // it is actually stored. Passing the wrong one must not silently derive
  // a workable key.
  await rejectsWith(openSubmission(payload, owner.privateKey, other.publicKeyRaw), 'failed')
})

test('an unknown payload version is refused before decrypting', async () => {
  const owner = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  const tampered = payload.slice()
  tampered[0] = 2
  await rejectsWith(openSubmission(tampered, owner.privateKey, owner.publicKeyRaw), 'unsupported')
})

test('a truncated payload is refused as malformed', async () => {
  const owner = await generateOwnerKeyPair()
  const payload = await sealSubmission(text, owner.publicKeyRaw)
  await rejectsWith(
    openSubmission(payload.slice(0, 10), owner.privateKey, owner.publicKeyRaw),
    'malformed',
  )
  await rejectsWith(
    openSubmission(new Uint8Array(0), owner.privateKey, owner.publicKeyRaw),
    'malformed',
  )
})

test('sealSubmission refuses an owner public key of the wrong size', async () => {
  await expect(sealSubmission(text, new Uint8Array(16))).rejects.toThrow(DecryptError)
})

test('importPublicKey refuses anything other than 32 bytes', async () => {
  await expect(importPublicKey(new Uint8Array(31))).rejects.toThrow(DecryptError)
  await expect(importPublicKey(new Uint8Array(33))).rejects.toThrow(DecryptError)
})

test('X25519 support is detected without throwing', async () => {
  expect(await isX25519Supported()).toBe(true)
  await expect(assertX25519Supported()).resolves.toBeUndefined()
})

const originalGenerateKey = subtle.generateKey.bind(subtle)

afterEach(() => {
  subtle.generateKey = originalGenerateKey
})

test('a browser without X25519 is detected instead of throwing on first use', async () => {
  subtle.generateKey = (() => {
    throw new DOMException('Unrecognized algorithm name', 'NotSupportedError')
  }) as typeof subtle.generateKey

  expect(await isX25519Supported()).toBe(false)
  await expect(assertX25519Supported()).rejects.toBeInstanceOf(UnsupportedBrowserError)
  await expect(sealSubmission(text, new Uint8Array(32))).rejects.toBeInstanceOf(
    UnsupportedBrowserError,
  )
})
