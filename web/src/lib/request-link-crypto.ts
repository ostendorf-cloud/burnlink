// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The request link's own crypto: the reverse flow where an owner publishes
// a link and a stranger seals a secret back to it while the owner is
// offline. Web Crypto only, no dependency, exactly like crypto.ts, which
// this file sits alongside and never imports anything mutable from.
//
// See docs/adr/0003-request-link-key-material.md, which this ports
// one-to-one:
//   - A sealed box over X25519: the sender generates an ephemeral keypair,
//     derives a shared secret against the owner's public key, runs
//     HKDF-SHA-256 over it to an AES-256-GCM key, encrypts, and lets the
//     ephemeral private key go out of scope. Nothing here ever stores an
//     ephemeral private key or reuses one.
//   - The HKDF info string binds this flow's own label, the ephemeral
//     public key and the owner's public key, in that order. Binding the
//     owner's key into the derivation (deriveSubmissionKey's third
//     argument), not only into the GCM additional data, is what separates
//     recipients: the additional data alone proves the header was not
//     altered, nothing about who it was sealed to.
//   - The derived AES key is never cached: deriveSubmissionKey has no
//     module-level state, is called once per seal or open, and its result
//     is used immediately by the same call and discarded with it. A random
//     12-byte IV is only safe because of that invariant, so there is
//     nowhere in this file a second caller could reach a stale key.
//   - The owner's public key travels only in the request link's own
//     fragment; nothing here ever sends it to or reads it from a server.
//   - The owner's private key is generated non-extractable; see
//     generateOwnerKeyPair for how an extractable public key still comes
//     out of the same generation.
//
// Payload, all binary, this flow's own version and layout, independent of
// crypto.ts's version 1:
//   version (1 byte) | ephemeral public key (32 bytes) | iv (12 bytes) |
//   AES-256-GCM ciphertext with 16 byte tag
// Everything before the ciphertext is the GCM additional data. There is no
// passphrase and no salt: nothing in docs/adr/0003 asks for one, and a
// request link's owner is never online at submission time to supply one.

import {
  DecryptError,
  decodeBase64,
  encodeBase64,
  type Bytes,
  type Content,
  type ContentInput,
} from './crypto'

export const SUBMISSION_VERSION = 1
export const OWNER_PUBLIC_KEY_BYTES = 32

const EPHEMERAL_PUBLIC_KEY_BYTES = 32
const IV_BYTES = 12
const TAG_BYTES = 16
const HEADER_BYTES = 1 + EPHEMERAL_PUBLIC_KEY_BYTES + IV_BYTES
// Plaintext is padded to a multiple of this, so the stored size does not
// reveal the length of a short submission; the same idea as crypto.ts's own
// PAD_BLOCK, kept independent so the two files never have to agree on one.
const PAD_BLOCK = 256

const HKDF_INFO_LABEL = new TextEncoder().encode('burnlink.de v1 requestlink')
// A distinct label from HKDF_INFO_LABEL: deriveOwnerAuth's output must never
// collide with a key deriveSubmissionKey could produce from the same ECDH
// input, which a shared label would risk.
const OWNER_AUTH_INFO = new TextEncoder().encode('burnlink.de v1 requestlink owner-auth')

const subtle = globalThis.crypto.subtle

/** Thrown when the running browser has no X25519 in Web Crypto. */
export class UnsupportedBrowserError extends Error {
  constructor() {
    super(
      'this browser cannot create or open a request link: X25519 is not available in Web Crypto',
    )
    this.name = 'UnsupportedBrowserError'
  }
}

/**
 * isX25519Supported reports whether the running browser's Web Crypto has
 * X25519, by generating and immediately discarding a throwaway keypair.
 * There is no capability flag to read instead: generateKey throwing
 * NotSupportedError is the documented way to detect an unknown algorithm.
 */
export async function isX25519Supported(): Promise<boolean> {
  try {
    await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
    return true
  } catch {
    return false
  }
}

/** assertX25519Supported throws UnsupportedBrowserError instead of letting a page's first real use fail on an opaque exception. */
export async function assertX25519Supported(): Promise<void> {
  if (!(await isX25519Supported())) {
    throw new UnsupportedBrowserError()
  }
}

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export interface OwnerKeyPair {
  publicKey: CryptoKey
  /** privateKey is non-extractable: exportKey on it always throws. */
  privateKey: CryptoKey
  publicKeyRaw: Bytes
}

/**
 * generateOwnerKeyPair returns a fresh X25519 keypair for a new request
 * link, with the invariant docs/adr/0003 requires: privateKey cannot be
 * exported, ever, by anything holding this module's return value.
 *
 * Web Crypto applies one extractable flag to both halves of a generated
 * pair, so there is no direct way to ask for an extractable public key
 * next to a non-extractable private one. This generates both extractable,
 * exports the public key's raw bytes (which is all a public key needs:
 * nothing about it is secret), then exports the private key once more, as
 * PKCS8, only to immediately reimport that same encoding as a new,
 * non-extractable CryptoKey, and overwrites the intermediate encoding
 * before returning. The extractable originals are not returned; only the
 * reimported, locked-down private key is.
 */
export async function generateOwnerKeyPair(): Promise<OwnerKeyPair> {
  await assertX25519Supported()

  // TypeScript's DOM typings do not know X25519 generates a pair the way
  // they know Ed25519 does, so generateKey's return type here falls back
  // to the generic CryptoKeyPair | CryptoKey overload; the cast reflects
  // what Web Crypto actually returns for an asymmetric algorithm.
  const extractablePair = (await subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair
  const publicKeyRaw = new Uint8Array(await subtle.exportKey('raw', extractablePair.publicKey))

  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', extractablePair.privateKey))
  const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, [
    'deriveBits',
  ])
  pkcs8.fill(0)

  return { publicKey: extractablePair.publicKey, privateKey, publicKeyRaw }
}

/** importPublicKey imports 32 raw bytes as an X25519 public key. */
export async function importPublicKey(raw: Bytes): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== OWNER_PUBLIC_KEY_BYTES) {
    throw new DecryptError('malformed', 'public key must be 32 bytes')
  }
  return subtle.importKey('raw', raw, { name: 'X25519' }, false, [])
}

/**
 * deriveSubmissionKey is the one place the AES key this flow uses comes
 * from. It has no state of its own and nothing it returns is ever written
 * back into it: every call is independent, which is what makes a fresh,
 * random IV safe to use with whatever it returns. Exported so a test can
 * hold ecdhBits fixed and vary ephemeralPublicKeyRaw or ownerPublicKeyRaw
 * on their own, something going through generateOwnerKeyPair and an actual
 * ECDH cannot isolate; sealSubmission and openSubmission are the only
 * other callers.
 */
export async function deriveSubmissionKey(
  ecdhBits: Bytes,
  ephemeralPublicKeyRaw: Bytes,
  ownerPublicKeyRaw: Bytes,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  const info = concat(HKDF_INFO_LABEL, ephemeralPublicKeyRaw, ownerPublicKeyRaw)
  const base = await subtle.importKey('raw', ecdhBits, 'HKDF', false, ['deriveKey'])
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  )
}

/**
 * deriveOwnerAuth returns the value only the holder of privateKey can
 * reproduce: a self-ECDH of the owner's own keypair (deriveBits accepts any
 * public key as the peer, including one's own), run through HKDF under a
 * label distinct from deriveSubmissionKey's. The server stores only its
 * SHA-256 digest, submitted once at creation; this function recomputes the
 * same value on every later visit so the owner never has to store it
 * separately from the private key it comes from.
 */
export async function deriveOwnerAuth(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Bytes> {
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256),
  )
  const base = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits'])
  bits.fill(0)
  return new Uint8Array(
    await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: OWNER_AUTH_INFO },
      base,
      256,
    ),
  )
}

function encodeContent(content: ContentInput): Bytes {
  let obj: Record<string, unknown>
  if (content && content.type === 'text' && typeof content.text === 'string') {
    obj = { type: 'text', text: content.text }
  } else if (
    content &&
    content.type === 'file' &&
    typeof content.name === 'string' &&
    content.data instanceof Uint8Array
  ) {
    obj = {
      type: 'file',
      name: content.name,
      mime: typeof content.mime === 'string' ? content.mime : '',
      data: encodeBase64(content.data),
    }
  } else {
    throw new TypeError(
      "content must be {type: 'text', text} or {type: 'file', name, mime, data: Uint8Array}",
    )
  }
  const json = new TextEncoder().encode(JSON.stringify(obj))
  const padded = new Uint8Array(Math.ceil((json.length + 1) / PAD_BLOCK) * PAD_BLOCK).fill(0x20)
  padded.set(json)
  return padded
}

function decodeContent(bytes: Bytes): Content {
  let obj: unknown
  try {
    obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new DecryptError('malformed', 'plaintext is not JSON')
  }
  if (isRecord(obj) && obj.type === 'text' && typeof obj.text === 'string') {
    return { type: 'text', text: obj.text }
  }
  if (
    isRecord(obj) &&
    obj.type === 'file' &&
    typeof obj.name === 'string' &&
    typeof obj.mime === 'string' &&
    typeof obj.data === 'string'
  ) {
    return { type: 'file', name: obj.name, mime: obj.mime, data: decodeBase64(obj.data) }
  }
  throw new DecryptError('malformed', 'unknown content')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export interface SubmissionHeader {
  ephemeralPublicKey: Bytes
  iv: Bytes
  header: Bytes
  ciphertext: Bytes
}

/** parseSubmissionHeader splits a submission payload without decrypting it. */
export function parseSubmissionHeader(payload: Bytes): SubmissionHeader {
  if (!(payload instanceof Uint8Array) || payload.length < HEADER_BYTES + TAG_BYTES) {
    throw new DecryptError('malformed', 'payload too short')
  }
  if (payload[0] !== SUBMISSION_VERSION) {
    throw new DecryptError('unsupported', 'unknown payload version')
  }
  return {
    ephemeralPublicKey: payload.subarray(1, 1 + EPHEMERAL_PUBLIC_KEY_BYTES),
    iv: payload.subarray(HEADER_BYTES - IV_BYTES, HEADER_BYTES),
    header: payload.subarray(0, HEADER_BYTES),
    ciphertext: payload.subarray(HEADER_BYTES),
  }
}

/**
 * sealSubmission encrypts content to ownerPublicKeyRaw and returns the
 * payload to submit. A fresh ephemeral keypair is generated for this call
 * only; nothing it derives is kept past this function returning.
 */
export async function sealSubmission(
  content: ContentInput,
  ownerPublicKeyRaw: Bytes,
): Promise<Bytes> {
  await assertX25519Supported()
  if (
    !(ownerPublicKeyRaw instanceof Uint8Array) ||
    ownerPublicKeyRaw.length !== OWNER_PUBLIC_KEY_BYTES
  ) {
    throw new DecryptError('malformed', 'owner public key must be 32 bytes')
  }
  const ownerPublicKey = await importPublicKey(ownerPublicKeyRaw)

  // Extractable only long enough to read its own public half back out; see
  // generateOwnerKeyPair's doc comment for why that is unavoidable. The
  // private half is used once, right below, and then never touched again:
  // this function returns nothing that could call deriveBits with it a
  // second time.
  const ephemeral = (await subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair
  const ephemeralPublicKeyRaw = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey))

  const sharedSecret = new Uint8Array(
    await subtle.deriveBits({ name: 'X25519', public: ownerPublicKey }, ephemeral.privateKey, 256),
  )
  const key = await deriveSubmissionKey(
    sharedSecret,
    ephemeralPublicKeyRaw,
    ownerPublicKeyRaw,
    'encrypt',
  )
  sharedSecret.fill(0)

  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const header = concat(new Uint8Array([SUBMISSION_VERSION]), ephemeralPublicKeyRaw, iv)
  const plaintext = encodeContent(content)
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      key,
      plaintext,
    ),
  )
  plaintext.fill(0)
  return concat(header, ciphertext)
}

/**
 * openSubmission decrypts payload with the owner's own keypair. privateKey
 * is expected to be the non-extractable key generateOwnerKeyPair produced;
 * publicKeyRaw is that same keypair's public half, needed because the HKDF
 * info it was sealed under binds it.
 */
export async function openSubmission(
  payload: Bytes,
  privateKey: CryptoKey,
  publicKeyRaw: Bytes,
): Promise<Content> {
  const { ephemeralPublicKey, header, ciphertext, iv } = parseSubmissionHeader(payload)
  const peer = await importPublicKey(ephemeralPublicKey)

  const sharedSecret = new Uint8Array(
    await subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256),
  )
  const key = await deriveSubmissionKey(sharedSecret, ephemeralPublicKey, publicKeyRaw, 'decrypt')
  sharedSecret.fill(0)

  let plaintext: Bytes
  try {
    plaintext = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
        key,
        ciphertext,
      ),
    )
  } catch {
    throw new DecryptError('failed', 'decryption failed')
  }
  try {
    return decodeContent(plaintext)
  } finally {
    plaintext.fill(0)
  }
}
