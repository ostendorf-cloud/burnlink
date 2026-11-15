// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// Where the owner's keypair actually lives: IndexedDB, the one browser
// storage that can hold a CryptoKey at all, through structured clone,
// without ever exposing its material to script. docs/adr/0003 settles
// that the private key stays here, non-extractable, with no exportable
// copy and no second private link; generateOwnerKeyPair in
// request-link-crypto.ts is what makes the key non-extractable in the
// first place, this file only ever stores and returns what it is given.
//
// This file is deliberately thin glue around indexedDB, with no decision
// of its own left to test: neither Node nor jsdom, which this repository's
// Vitest setup runs on, implements IndexedDB, and adding a dependency to
// shim one for a handful of put/get calls was not judged worth it. Every
// property docs/adr/0003 actually requires of the stored key, non-
// extractability chief among them, is proven in request-link-crypto.test.ts
// against the real Web Crypto API instead, independently of where the key
// ends up stored.

import type { Bytes } from './crypto'
import type { OwnerKeyPair } from './request-link-crypto'

const DATABASE_NAME = 'burnlink-request-links'
const DATABASE_VERSION = 1
const STORE_NAME = 'owner-keys'

interface StoredRecord {
  id: string
  publicKey: CryptoKey
  privateKey: CryptoKey
  publicKeyRaw: Bytes
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME, { keyPath: 'id' })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('indexedDB.open failed'))
  })
}

/** saveOwnerKey stores id's keypair, replacing whatever was stored for it before. */
export async function saveOwnerKey(id: string, keyPair: OwnerKeyPair): Promise<void> {
  const db = await openDatabase()
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite')
      const record: StoredRecord = {
        id,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        publicKeyRaw: keyPair.publicKeyRaw,
      }
      tx.objectStore(STORE_NAME).put(record)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB transaction failed'))
    })
  } finally {
    db.close()
  }
}

/** loadOwnerKey returns id's stored keypair, or null if this browser never created or has since lost one. */
export async function loadOwnerKey(id: string): Promise<OwnerKeyPair | null> {
  const db = await openDatabase()
  try {
    const record = await new Promise<StoredRecord | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly')
      const request = tx.objectStore(STORE_NAME).get(id)
      request.onsuccess = () => resolve(request.result as StoredRecord | undefined)
      request.onerror = () => reject(request.error ?? new Error('indexedDB read failed'))
    })
    if (!record) {
      return null
    }
    return {
      publicKey: record.publicKey,
      privateKey: record.privateKey,
      publicKeyRaw: record.publicKeyRaw,
    }
  } finally {
    db.close()
  }
}

/** hasOwnerKey reports whether this browser holds a keypair for id, without exposing it. */
export async function hasOwnerKey(id: string): Promise<boolean> {
  return (await loadOwnerKey(id)) !== null
}

/**
 * requestPersistentStorage asks the browser not to evict this origin's
 * storage under pressure. Best effort: docs/adr/0003 names it as the one
 * lever this page has against eviction, not a guarantee, and a browser
 * without the API at all is treated the same as one that declines.
 */
export async function requestPersistentStorage(): Promise<boolean> {
  try {
    return (await navigator.storage?.persist?.()) ?? false
  } catch {
    return false
  }
}
