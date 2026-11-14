// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// End to end encryption of a secret, WebCrypto only. Runs in the browser and
// in Node for the tests. Ported from old_burnlink's web/src/lib/crypto.ts: see
// docs/adr/0002-the-payload-format-stays-from-old-burnlink.md for why this
// file is a port rather than a rewrite.
//
// Payload, all binary:
//   version (1 byte) | flags (1 byte) | salt (16 bytes, only with a
//   passphrase) | iv (12 bytes) | AES-256-GCM ciphertext with 16 byte tag
// The header, everything before the ciphertext, is the GCM additional data,
// so flipping the passphrase flag or swapping the salt breaks decryption.
//
// The server never sees any of this: it stores the payload, and the link key
// lives in the fragment of the link, which a browser does not send.

export const VERSION = 1
export const FLAG_PASSPHRASE = 0x01
const KNOWN_FLAGS = FLAG_PASSPHRASE

export const KEY_BYTES = 32
const IV_BYTES = 12
const SALT_BYTES = 16
const TAG_BYTES = 16
// Fixed per payload version, never read from the payload, so a forged payload
// cannot lower it.
export const PBKDF2_ITERATIONS = 600000
const HKDF_INFO = new TextEncoder().encode('burnlink.de v1 aes-256-gcm')
// Plaintext is padded to a multiple of this, so the stored size does not
// reveal the length of a short secret.
const PAD_BLOCK = 256

const subtle = globalThis.crypto.subtle

/**
 * Bytes are backed by a plain ArrayBuffer, which is what WebCrypto takes: a
 * bare Uint8Array may sit on a SharedArrayBuffer and is not accepted there.
 */
export type Bytes = Uint8Array<ArrayBuffer>

/** Why a payload could not be opened. */
export type DecryptCode = 'malformed' | 'unsupported' | 'passphrase_required' | 'failed'

export class DecryptError extends Error {
  readonly code: DecryptCode

  constructor(code: DecryptCode, message: string) {
    super(message)
    this.name = 'DecryptError'
    this.code = code
  }
}

/** Content is what a secret holds: a text, or a file with its bytes. */
export type Content =
  { type: 'text'; text: string } | { type: 'file'; name: string; mime: string; data: Bytes }

/** ContentInput is what the page hands in; the mime type may be missing. */
export type ContentInput =
  { type: 'text'; text: string } | { type: 'file'; name: string; mime?: string; data: Bytes }

/** Header is a payload split up, without decrypting it. */
export interface Header {
  hasPassphrase: boolean
  salt: Bytes | null
  iv: Bytes
  header: Bytes
  ciphertext: Bytes
}

export function generateLinkKey(): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(KEY_BYTES))
}

// ---------- base64 ----------

const URL_ALPHABET = /^[A-Za-z0-9_-]*$/
const STD_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/

function bytesToBinary(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return out
}

function binaryToBytes(binary: string): Bytes {
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function encodeBase64(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes))
}

export function encodeBase64url(bytes: Uint8Array): string {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Strict: only the alphabet, no padding, canonical trailing bits. Throws on
// anything else, so a link that was mangled on the way fails here rather than
// as a decryption failure nobody can explain.
export function decodeBase64url(text: unknown): Bytes {
  if (typeof text !== 'string' || !URL_ALPHABET.test(text) || text.length % 4 === 1) {
    throw new DecryptError('malformed', 'not base64url')
  }
  const std = text.replace(/-/g, '+').replace(/_/g, '/')
  const bytes = binaryToBytes(atob(std + '='.repeat((4 - (std.length % 4)) % 4)))
  if (encodeBase64url(bytes) !== text) {
    throw new DecryptError('malformed', 'not canonical base64url')
  }
  return bytes
}

export function decodeBase64(text: unknown): Bytes {
  if (typeof text !== 'string' || text.length % 4 !== 0 || !STD_ALPHABET.test(text)) {
    throw new DecryptError('malformed', 'not base64')
  }
  const bytes = binaryToBytes(atob(text))
  if (encodeBase64(bytes) !== text) {
    throw new DecryptError('malformed', 'not canonical base64')
  }
  return bytes
}

// ---------- keys ----------

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

// The AES key comes from HKDF over the link key, and with a passphrase over
// the link key followed by the PBKDF2 output, so both are needed.
async function deriveKey(
  linkKey: Bytes,
  passphrase: string,
  salt: Bytes | null,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  if (!(linkKey instanceof Uint8Array) || linkKey.length !== KEY_BYTES) {
    throw new DecryptError('malformed', 'link key must be 32 bytes')
  }
  let ikm: Bytes = linkKey
  let hkdfSalt: Bytes = new Uint8Array(0)
  if (salt) {
    const pass = await subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase.normalize('NFC')),
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    const stretched = new Uint8Array(
      await subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
        pass,
        256,
      ),
    )
    ikm = concat(linkKey, stretched)
    stretched.fill(0)
    hkdfSalt = salt
  }
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  if (ikm !== linkKey) ikm.fill(0)
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: HKDF_INFO },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  )
}

// ---------- plaintext ----------

function encodeContent(content: ContentInput): Bytes {
  // The shape is checked at runtime, not only by the type: the caller may be
  // holding something that came out of a file picker.
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
  // JSON.parse ignores trailing white space, so spaces pad without a length
  // field of their own.
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
  // Authentic plaintext is still plaintext someone else wrote: nothing is
  // trusted beyond the shape this version knows.
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

// ---------- payload ----------

/** parseHeader splits a payload without decrypting it. */
export function parseHeader(payload: Bytes): Header {
  if (!(payload instanceof Uint8Array) || payload.length < 2) {
    throw new DecryptError('malformed', 'payload too short')
  }
  if (payload[0] !== VERSION) {
    throw new DecryptError('unsupported', 'unknown payload version')
  }
  const flags = payload[1]
  if ((flags & ~KNOWN_FLAGS) !== 0) {
    throw new DecryptError('unsupported', 'unknown flags')
  }
  const hasPassphrase = (flags & FLAG_PASSPHRASE) !== 0
  const headerLength = 2 + (hasPassphrase ? SALT_BYTES : 0) + IV_BYTES
  if (payload.length < headerLength + TAG_BYTES) {
    throw new DecryptError('malformed', 'payload too short')
  }
  return {
    hasPassphrase,
    salt: hasPassphrase ? payload.subarray(2, 2 + SALT_BYTES) : null,
    iv: payload.subarray(headerLength - IV_BYTES, headerLength),
    header: payload.subarray(0, headerLength),
    ciphertext: payload.subarray(headerLength),
  }
}

export function needsPassphrase(payload: Bytes): boolean {
  return parseHeader(payload).hasPassphrase
}

/**
 * encryptSecret returns the payload for content under linkKey, and the
 * passphrase when it is not empty.
 */
export async function encryptSecret(
  content: ContentInput,
  linkKey: Bytes,
  passphrase = '',
): Promise<Bytes> {
  const hasPassphrase = typeof passphrase === 'string' && passphrase.length > 0
  const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n))
  const salt = hasPassphrase ? rand(SALT_BYTES) : null
  const iv = rand(IV_BYTES)
  const header = concat(
    new Uint8Array([VERSION, hasPassphrase ? FLAG_PASSPHRASE : 0]),
    salt ?? new Uint8Array(0),
    iv,
  )
  const key = await deriveKey(linkKey, passphrase, salt, 'encrypt')
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

/** decryptSecret returns the content, or throws a DecryptError. */
export async function decryptSecret(
  payload: Bytes,
  linkKey: Bytes,
  passphrase = '',
): Promise<Content> {
  const { hasPassphrase, salt, iv, header, ciphertext } = parseHeader(payload)
  if (hasPassphrase && (typeof passphrase !== 'string' || passphrase.length === 0)) {
    throw new DecryptError('passphrase_required', 'a passphrase is required')
  }
  const key = await deriveKey(linkKey, hasPassphrase ? passphrase : '', salt, 'decrypt')
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
