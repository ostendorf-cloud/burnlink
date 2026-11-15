// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The owner's only durable copy of what a request link's open endpoint
// already removed from the server. The store is deliberately read-once
// (internal/webapp/requestlink's GetDel): the instant the owner's browser
// has decrypted a submission, the server no longer holds it anywhere, so
// this IndexedDB record is the one remaining copy. A reload, a navigation
// or a crash must still show it; CreateRequestLink.vue's own loss notice
// already tells the owner that losing this browser's storage loses every
// submission permanently, and this file is what makes that statement, and
// its mirror image, true.
//
// Thin IndexedDB glue, the same shape as request-link-keys.ts and
// deliberately untested directly for the same reason: neither Node nor
// jsdom, which this repository's Vitest setup runs on, implements
// IndexedDB. RequestLinkView.test.ts mocks this module at the boundary and
// proves the one behaviour that actually matters here from the caller's
// side: a submission is never shown as received unless it was saved first.

import type { Content } from './crypto'

const DATABASE_NAME = 'burnlink-request-link-submissions'
const DATABASE_VERSION = 1
const STORE_NAME = 'submissions'

interface StoredRecord {
  id: string
  submissions: Content[]
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

/** loadSubmissions returns every submission this browser has already saved for id, oldest first. */
export async function loadSubmissions(id: string): Promise<Content[]> {
  const db = await openDatabase()
  try {
    const record = await new Promise<StoredRecord | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly')
      const request = tx.objectStore(STORE_NAME).get(id)
      request.onsuccess = () => resolve(request.result as StoredRecord | undefined)
      request.onerror = () => reject(request.error ?? new Error('indexedDB read failed'))
    })
    return record?.submissions ?? []
  } finally {
    db.close()
  }
}

/**
 * appendSubmissions durably saves newSubmissions next to whatever this
 * browser already saved for id, in one read-modify-write transaction, and
 * returns the full saved list including them.
 *
 * By the time a caller has decrypted newSubmissions, the server has
 * already deleted its own copy of each one: open's GetDel removes a
 * submission from the store before this browser has done anything with it.
 * A rejection here therefore means newSubmissions are gone, with no copy
 * left anywhere to fall back to. A caller must not show them as received
 * when this rejects; it must say they were lost instead.
 */
export async function appendSubmissions(id: string, newSubmissions: Content[]): Promise<Content[]> {
  const db = await openDatabase()
  try {
    return await new Promise<Content[]>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite')
      const store = tx.objectStore(STORE_NAME)
      let merged: Content[] = newSubmissions

      const getRequest = store.get(id)
      getRequest.onsuccess = () => {
        const existing = (getRequest.result as StoredRecord | undefined)?.submissions ?? []
        merged = [...existing, ...newSubmissions]
        store.put({ id, submissions: merged } satisfies StoredRecord)
      }
      getRequest.onerror = () => reject(getRequest.error ?? new Error('indexedDB read failed'))

      tx.oncomplete = () => resolve(merged)
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB transaction failed'))
    })
  } finally {
    db.close()
  }
}
