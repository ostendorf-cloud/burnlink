// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// WebCrypto, not jsdom: jsdom ships no SubtleCrypto, and this module has no
// DOM access of its own.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test } from 'vitest'

import {
  DecryptError,
  FLAG_PASSPHRASE,
  KEY_BYTES,
  PBKDF2_ITERATIONS,
  VERSION,
  decodeBase64,
  decodeBase64url,
  decryptSecret,
  encodeBase64,
  encodeBase64url,
  encryptSecret,
  generateLinkKey,
  needsPassphrase,
  parseHeader,
  type Bytes,
  type Content,
  type DecryptCode,
} from './crypto'

// Passphrases cost 600000 PBKDF2 iterations each, so the tests that use one
// get a timeout that is not the default five seconds.
const slow = 60_000

const text: Content = { type: 'text', text: 'correct horse battery staple ✓ äöü\n\t"quoted"' }

async function rejectsWith(promise: Promise<unknown>, code: DecryptCode) {
  const error = await promise.then(
    () => null,
    (err: unknown) => err,
  )
  expect(error, 'the promise resolved instead of failing').toBeInstanceOf(DecryptError)
  expect((error as DecryptError).code).toBe(code)
}

test('link keys are 32 random bytes', () => {
  const a = generateLinkKey()
  const b = generateLinkKey()
  expect(a).toHaveLength(KEY_BYTES)
  expect(a).not.toEqual(b)
  expect(PBKDF2_ITERATIONS).toBe(600000)
})

test('text round trip without passphrase', async () => {
  const key = generateLinkKey()
  const payload = await encryptSecret(text, key)
  expect(payload[0]).toBe(VERSION)
  expect(payload[1]).toBe(0)
  expect(needsPassphrase(payload)).toBe(false)
  // version, flags, IV, ciphertext padded to 256, tag
  expect(payload).toHaveLength(2 + 12 + 256 + 16)
  expect(await decryptSecret(payload, key)).toEqual(text)
})

test('the same secret encrypts differently every time', async () => {
  const key = generateLinkKey()
  const a = await encryptSecret(text, key)
  const b = await encryptSecret(text, key)
  expect(a).not.toEqual(b)
  expect(parseHeader(a).iv).not.toEqual(parseHeader(b).iv)
})

test('padding hides the length of short secrets', async () => {
  const key = generateLinkKey()
  const short = await encryptSecret({ type: 'text', text: 'a' }, key)
  const longer = await encryptSecret({ type: 'text', text: 'a much longer password 123456' }, key)
  expect(short.length).toBe(longer.length)
})

test('file round trip keeps bytes, name and type', async () => {
  const key = generateLinkKey()
  const data = new Uint8Array(70000)
  for (let i = 0; i < data.length; i++) data[i] = (i * 31 + 7) & 0xff
  const file = {
    type: 'file' as const,
    name: '../id_ed25519',
    mime: 'application/x-pem-file',
    data,
  }
  const payload = await encryptSecret(file, key)
  const out = await decryptSecret(payload, key)
  expect(out).toEqual(file)
})

test(
  'file round trip with a passphrase keeps bytes, name and type',
  async () => {
    const key = generateLinkKey()
    const data = new Uint8Array(1000)
    for (let i = 0; i < data.length; i++) data[i] = (i * 17 + 3) & 0xff
    const file = {
      type: 'file' as const,
      name: 'backup-codes.txt',
      mime: 'text/plain',
      data,
    }
    const payload = await encryptSecret(file, key, 'tr0ub4dor&3')
    expect(needsPassphrase(payload)).toBe(true)
    const out = await decryptSecret(payload, key, 'tr0ub4dor&3')
    expect(out).toEqual(file)
  },
  slow,
)

test('wrong link key fails', async () => {
  const payload = await encryptSecret(text, generateLinkKey())
  await rejectsWith(decryptSecret(payload, generateLinkKey()), 'failed')
})

test('link keys of the wrong size are refused', async () => {
  await expect(encryptSecret(text, new Uint8Array(16))).rejects.toThrow(DecryptError)
  const payload = await encryptSecret(text, generateLinkKey())
  await rejectsWith(decryptSecret(payload, new Uint8Array(31)), 'malformed')
})

test(
  'passphrase round trip needs both factors',
  async () => {
    const key = generateLinkKey()
    const payload = await encryptSecret(text, key, 'tr0ub4dor&3')
    expect(payload[1]).toBe(FLAG_PASSPHRASE)
    expect(needsPassphrase(payload)).toBe(true)
    expect(parseHeader(payload).salt).toHaveLength(16)
    expect(payload).toHaveLength(2 + 16 + 12 + 256 + 16)

    expect(await decryptSecret(payload, key, 'tr0ub4dor&3')).toEqual(text)
    await rejectsWith(decryptSecret(payload, key), 'passphrase_required')
    await rejectsWith(decryptSecret(payload, key, 'Tr0ub4dor&3'), 'failed')
    // The right passphrase with the wrong link key is not enough either.
    await rejectsWith(decryptSecret(payload, generateLinkKey(), 'tr0ub4dor&3'), 'failed')
  },
  slow,
)

test(
  'passphrases are compared after Unicode normalisation',
  async () => {
    const key = generateLinkKey()
    // The two passphrases below are typed characters, which an editor or a
    // formatter that normalises this file could collapse into one byte
    // sequence, turning this into a test that passes no matter what
    // encrypts and what decrypts. The assertion right after them fails if
    // that ever happens. The passphrase that encrypts is one code point,
    // U+00E9 "e with acute accent"; the one that decrypts is the decomposed
    // form, "e" followed by the combining acute accent U+0301. The two look
    // identical and are not the same bytes. The README never mentions
    // Unicode normalisation, so this test is the only thing holding
    // deriveKey's passphrase.normalize('NFC') to that part of the contract;
    // without it the two forms derive different keys and decryption fails.
    const precomposed = 'Café'
    const decomposed = 'Café'
    expect(precomposed).not.toBe(decomposed)
    const payload = await encryptSecret(text, key, precomposed)
    expect(await decryptSecret(payload, key, decomposed)).toEqual(text)
  },
  slow,
)

test(
  'flipping the passphrase flag breaks decryption instead of changing the result',
  async () => {
    const key = generateLinkKey()
    const plain = await encryptSecret(text, key)
    const protectedPayload = await encryptSecret(text, key, 'pass')

    // An unknown version and unknown flags are refused before decrypting.
    const version = plain.slice()
    version[0] = 2
    await rejectsWith(decryptSecret(version, key), 'unsupported')
    const flags = plain.slice()
    flags[1] = 0x80
    await rejectsWith(decryptSecret(flags, key), 'unsupported')

    // Removing the passphrase flag shifts the layout and changes the key.
    const stripped = protectedPayload.slice()
    stripped[1] = 0
    await rejectsWith(decryptSecret(stripped, key, 'pass'), 'failed')

    // Adding the flag to a payload that has none.
    const added = plain.slice()
    added[1] = FLAG_PASSPHRASE
    await rejectsWith(decryptSecret(added, key, 'pass'), 'failed')
  },
  slow,
)

test(
  'swapping the salt or the IV breaks decryption instead of changing the result',
  async () => {
    const key = generateLinkKey()
    const plain = await encryptSecret(text, key)
    const protectedPayload = await encryptSecret(text, key, 'pass')

    // A changed salt or IV breaks the additional data or the key.
    for (const index of [2, 17, 18, 29]) {
      const tampered = protectedPayload.slice()
      tampered[index] ^= 0x01
      await rejectsWith(decryptSecret(tampered, key, 'pass'), 'failed')
    }
    for (const index of [2, 13]) {
      const tampered = plain.slice()
      tampered[index] ^= 0x01
      await rejectsWith(decryptSecret(tampered, key), 'failed')
    }
  },
  slow,
)

test('tampered ciphertext and tag fail', async () => {
  const key = generateLinkKey()
  const payload = await encryptSecret(text, key)
  for (const index of [14, 100, payload.length - 17, payload.length - 1]) {
    const tampered = payload.slice()
    tampered[index] ^= 0x80
    await rejectsWith(decryptSecret(tampered, key), 'failed')
  }
  await rejectsWith(decryptSecret(payload.slice(0, payload.length - 1), key), 'failed')
  await rejectsWith(decryptSecret(payload.slice(0, 20), key), 'malformed')
  await rejectsWith(decryptSecret(new Uint8Array(0), key), 'malformed')
  const extended = new Uint8Array(payload.length + 1)
  extended.set(payload)
  await rejectsWith(decryptSecret(extended, key), 'failed')
})

test('base64url is strict', () => {
  for (const n of [0, 1, 2, 3, 16, 32, 100]) {
    const bytes = new Uint8Array(n)
    bytes.set(generateLinkKey().slice(0, n))
    const encoded = encodeBase64url(bytes)
    expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/)
    expect(decodeBase64url(encoded)).toEqual(bytes)
  }
  expect(encodeBase64url(generateLinkKey())).toHaveLength(43)

  const key = encodeBase64url(generateLinkKey())
  const bad: unknown[] = [
    key + '=',
    key.slice(0, 42) + '+',
    key + ' ',
    key + '\n',
    'A',
    key.slice(0, 42) + 'B',
    42,
    null,
  ]
  for (const value of bad) {
    expect(() => decodeBase64url(value), `accepted ${JSON.stringify(value)}`).toThrow(DecryptError)
  }
})

test('standard base64 for file data is strict', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253])
  expect(decodeBase64(encodeBase64(bytes))).toEqual(bytes)
  for (const value of ['AAA', 'AA=A', 'AB==', 'A-_A', 'AAAA\n']) {
    expect(() => decodeBase64(value), `accepted ${value}`).toThrow(DecryptError)
  }
})

test('encryption refuses content of an unknown shape', async () => {
  const key = generateLinkKey()
  const unknownShapes = [
    { type: 'html', text: '<b>x</b>' },
    { type: 'file', name: 'a', data: 'not bytes' },
    null,
  ]
  for (const content of unknownShapes) {
    await expect(
      encryptSecret(content as unknown as Content, key),
      `accepted ${JSON.stringify(content)}`,
    ).rejects.toThrow(TypeError)
  }
})

// sealV1 builds a payload straight from the documented format: README.md's
// layout, HKDF-SHA-256 over the link key with the fixed info string, and
// AES-256-GCM with the header as additional data. It does not call anything
// from crypto.ts, on purpose, so it still fails the test below when the
// implementation drifts from the documented contract rather than agreeing
// with whatever crypto.ts happens to do.
async function sealV1(linkKey: Bytes, passphrase: string, plaintext: Bytes): Promise<Bytes> {
  const subtle = globalThis.crypto.subtle
  const textEncoder = new TextEncoder()
  let salt: Bytes | null = null
  let ikm: Bytes = linkKey
  if (passphrase) {
    salt = globalThis.crypto.getRandomValues(new Uint8Array(16))
    const passphraseKey = await subtle.importKey(
      'raw',
      textEncoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    const stretched = new Uint8Array(
      await subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 },
        passphraseKey,
        256,
      ),
    )
    ikm = new Uint8Array([...linkKey, ...stretched])
  }
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  const aes = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt ?? new Uint8Array(0),
      info: textEncoder.encode('burnlink.de v1 aes-256-gcm'),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const header = new Uint8Array([1, passphrase ? 1 : 0, ...(salt ?? []), ...iv])
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      aes,
      plaintext,
    ),
  )
  return new Uint8Array([...header, ...ciphertext])
}

// openV1 is sealV1's mirror: an independent reader of the documented format
// that decrypts a payload instead of building one. It imports nothing from
// crypto.ts either, so it checks the other direction, what encryptSecret
// writes, with the same independence sealV1 gives the open direction.
async function openV1(linkKey: Bytes, passphrase: string, payload: Bytes): Promise<Bytes> {
  const subtle = globalThis.crypto.subtle
  const textEncoder = new TextEncoder()
  const hasPassphrase = (payload[1] & 0x01) !== 0
  const salt = hasPassphrase ? payload.subarray(2, 2 + 16) : null
  const ivStart = hasPassphrase ? 2 + 16 : 2
  const iv = payload.subarray(ivStart, ivStart + 12)
  const header = payload.subarray(0, ivStart + 12)
  const ciphertext = payload.subarray(ivStart + 12)
  let ikm: Bytes = linkKey
  if (salt) {
    const passphraseKey = await subtle.importKey(
      'raw',
      textEncoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    const stretched = new Uint8Array(
      await subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 },
        passphraseKey,
        256,
      ),
    )
    ikm = new Uint8Array([...linkKey, ...stretched])
  }
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  const aes = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt ?? new Uint8Array(0),
      info: textEncoder.encode('burnlink.de v1 aes-256-gcm'),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )
  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
      aes,
      ciphertext,
    ),
  )
}

test('an independent reader of the documented format opens what encryptSecret wrote', async () => {
  const key = generateLinkKey()
  const payload = await encryptSecret(text, key)
  const plaintext = new TextDecoder().decode(await openV1(key, '', payload))
  expect(JSON.parse(plaintext)).toEqual({ type: text.type, text: text.text })
})

test(
  'an independent reader of the documented format opens what encryptSecret wrote with a passphrase',
  async () => {
    const key = generateLinkKey()
    const payload = await encryptSecret(text, key, 'tr0ub4dor&3')
    const plaintext = new TextDecoder().decode(await openV1(key, 'tr0ub4dor&3', payload))
    expect(JSON.parse(plaintext)).toEqual({ type: text.type, text: text.text })
  },
  slow,
)

test('a payload built from the documented format without a passphrase decrypts', async () => {
  const key = generateLinkKey()
  const payload = await sealV1(
    key,
    '',
    new TextEncoder().encode('{"type":"text","text":"from the spec"}   '),
  )
  expect(await decryptSecret(payload, key)).toEqual({ type: 'text', text: 'from the spec' })
})

test('a payload built from the documented format with a passphrase decrypts', async () => {
  const key = generateLinkKey()
  const payload = await sealV1(
    key,
    'tr0ub4dor&3',
    new TextEncoder().encode('{"type":"text","text":"from the spec, behind a passphrase"}'),
  )
  // The literal from README.md's layout, not FLAG_PASSPHRASE: this test's
  // point is that the documented flags byte is 1 for a passphrase, checked
  // without borrowing the value from the implementation it is meant to pin.
  expect(payload[1]).toBe(1)
  expect(await decryptSecret(payload, key, 'tr0ub4dor&3')).toEqual({
    type: 'text',
    text: 'from the spec, behind a passphrase',
  })
})

test('authentic plaintext of the wrong shape is refused', async () => {
  const key = generateLinkKey()
  const encode = (s: string) => new TextEncoder().encode(s)
  const plaintexts = [
    encode('{"type":"html","text":"<img src=x onerror=alert(1)>"}'),
    encode('{"type":"text","text":5}'),
    encode('{"type":"text"}'),
    encode('{"type":"file","name":"a","mime":"text/plain","data":"not base64!"}'),
    encode('{"type":"file","name":["a"],"mime":"text/plain","data":"AAAA"}'),
    encode('null'),
    encode('[]'),
    encode('not json'),
    new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]),
  ]
  for (const plaintext of plaintexts) {
    await rejectsWith(decryptSecret(await sealV1(key, '', plaintext), key), 'malformed')
  }
})

// The fixtures below are checked in under testdata/ as a historical
// artefact: two payloads built outside this test run, padded to a multiple
// of 256 the way encodeContent() pads a real one, to stand in for a link
// old_burnlink itself would have issued and a link holder's own fragment.
// Neither the key bytes nor the passphrase here protect a real secret: both
// are public in this file.
//
// An equivalent fixture is reproducible from inside the repository without
// checking anything new in: pad the plaintext to a multiple of 256 and seal
// it with sealV1 above, which builds the same documented format the
// checked in fixtures were built from. The test after the two below does
// exactly that, so the shape a real link has is evidence this repository
// can audit and regenerate on its own, not only read from a binary file.
function readFixture(name: string): Bytes {
  return new Uint8Array(readFileSync(join(import.meta.dirname, 'testdata', name)))
}

test('a link issued by the predecessor opens here', async () => {
  const linkKey = Uint8Array.from({ length: 32 }, (_, i) => i)
  const payload = readFixture('old-burnlink-text.v1')
  expect(needsPassphrase(payload)).toBe(false)
  expect(await decryptSecret(payload, linkKey)).toEqual({
    type: 'text',
    text: 'a secret the predecessor already sent',
  })
})

test('a passphrase protected link issued by the predecessor opens here', async () => {
  const linkKey = Uint8Array.from({ length: 32 }, (_, i) => 31 - i)
  const payload = readFixture('old-burnlink-text-with-passphrase.v1')
  expect(needsPassphrase(payload)).toBe(true)
  expect(await decryptSecret(payload, linkKey, 'correct horse battery staple')).toEqual({
    type: 'text',
    text: 'a secret that needed a passphrase',
  })
})

function padLikeARealPayload(json: string): Bytes {
  const bytes = new TextEncoder().encode(json)
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / 256) * 256).fill(0x20)
  padded.set(bytes)
  return padded
}

test('a padded payload built from the documented format has the shape a real link has', async () => {
  const key = generateLinkKey()
  const plaintext = padLikeARealPayload(
    JSON.stringify({ type: 'text', text: 'a secret the predecessor already sent' }),
  )
  const payload = await sealV1(key, '', plaintext)
  // version, flags, iv, 256 byte padded plaintext, tag: the same total a
  // real unprotected link leaves, and what old-burnlink-text.v1 now is.
  expect(payload).toHaveLength(2 + 12 + 256 + 16)
  expect(await decryptSecret(payload, key)).toEqual({
    type: 'text',
    text: 'a secret the predecessor already sent',
  })
})
