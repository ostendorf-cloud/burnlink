// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The one time secret's own calls against internal/webapp/secrets, through
// govue's ApiClient. Only ciphertext goes out and comes back: the link key
// never reaches this file.

import type { ApiClient } from '@ostendorf-cloud/govue'

import { decodeBase64, encodeBase64, type Bytes } from './crypto'

export interface SecretConfig {
  maxCiphertextBytes: number
  lifetime: { minSeconds: number; maxSeconds: number; defaultSeconds: number }
}

export interface StoredSecret {
  id: string
  expiresAt: Date
}

/** getConfig reads the limits the page enforces before it sends anything. */
export function getConfig(client: ApiClient): Promise<SecretConfig> {
  return client.get<SecretConfig>('/config')
}

/**
 * storeSecret uploads a payload and returns the id the server chose. A
 * notifyUrl is the optional webhook the server calls once when the secret is
 * opened. It is the one plain text value besides the id that the server
 * stores and so learns, and it is sent only when the sender typed one.
 */
export async function storeSecret(
  client: ApiClient,
  payload: Bytes,
  lifetimeSeconds?: number,
  notifyUrl?: string,
): Promise<StoredSecret> {
  const body: { ciphertext: string; lifetimeSeconds?: number; notifyUrl?: string } = {
    ciphertext: encodeBase64(payload),
  }
  if (lifetimeSeconds !== undefined) body.lifetimeSeconds = lifetimeSeconds
  if (notifyUrl) body.notifyUrl = notifyUrl
  const resp = await client.post<{ id: string; expiresAt: string }>('/secrets', body)
  return { id: resp.id, expiresAt: new Date(resp.expiresAt) }
}

/**
 * openSecret reads and deletes the secret id names. The server removes it in
 * the same step: a caller that loses the answer cannot ask again.
 */
export async function openSecret(client: ApiClient, id: string): Promise<Bytes> {
  const resp = await client.post<{ ciphertext: string }>(
    `/secrets/${encodeURIComponent(id)}/open`,
    {},
  )
  return decodeBase64(resp.ciphertext)
}
