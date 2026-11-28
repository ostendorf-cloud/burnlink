// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// The web half of the cross language check. internal/payload reads the same
// file in Go and has to agree on every byte. Change the format and one side
// or both fail. Regenerate the payloads from the Go side:
// go test ./internal/payload -run TestVectors -update
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, expect, test, vi } from 'vitest'

import {
  decodeBase64,
  decryptSecret,
  encodeBase64,
  encryptSecret,
  type Bytes,
  type Content,
  type ContentInput,
} from './crypto'

interface Vector {
  name: string
  linkKey: string
  passphrase: string
  salt: string
  iv: string
  content:
    { kind: 'text'; text: string } | { kind: 'file'; name: string; mime: string; data: string }
  payload: string
}

// Passphrases cost 600000 PBKDF2 iterations per call, twice in this test.
const slow = 60_000

const vectors = (
  JSON.parse(
    readFileSync(join(import.meta.dirname, '../../../testdata/format/vectors.json'), 'utf8'),
  ) as { vectors: Vector[] }
).vectors

function fromHex(hex: string): Bytes {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function contentOf(v: Vector): { input: ContentInput; expected: Content } {
  if (v.content.kind === 'text') {
    const text = { type: 'text' as const, text: v.content.text }
    return { input: text, expected: text }
  }
  const file = {
    type: 'file' as const,
    name: v.content.name,
    mime: v.content.mime,
    data: decodeBase64(v.content.data),
  }
  return { input: file, expected: file }
}

afterEach(() => {
  vi.restoreAllMocks()
})

test('the vectors cover text, a file and a passphrase', () => {
  expect(vectors.some((v) => v.content.kind === 'text' && v.passphrase === '')).toBe(true)
  expect(vectors.some((v) => v.content.kind === 'file' && v.passphrase === '')).toBe(true)
  expect(vectors.some((v) => v.passphrase !== '')).toBe(true)
  // An editor that normalises the file would let the NFC check pass for the
  // wrong reason.
  expect(vectors.some((v) => v.passphrase !== v.passphrase.normalize('NFC'))).toBe(true)
})

for (const v of vectors) {
  test(
    `vector: ${v.name}`,
    async () => {
      const linkKey = fromHex(v.linkKey)
      const payload = decodeBase64(v.payload)
      const { input, expected } = contentOf(v)

      // Opens what the Go side wrote.
      expect(await decryptSecret(payload, linkKey, v.passphrase)).toEqual(expected)

      // Writes the same bytes with the same salt and IV, in the order the
      // page asks for them: the salt first, then the IV.
      const queue = [v.salt, v.iv].filter((hex) => hex !== '').map(fromHex)
      vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((array: Uint8Array) => {
        const next = queue.shift()
        if (!next || next.length !== array.length) {
          throw new Error('unexpected request for random bytes')
        }
        array.set(next)
        return array
      }) as typeof globalThis.crypto.getRandomValues)
      const sealed = await encryptSecret(input, linkKey, v.passphrase)
      expect(queue).toHaveLength(0)
      expect(encodeBase64(sealed)).toBe(v.payload)
    },
    slow,
  )
}
