// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// The request link's own calls against internal/webapp/requestlink's three
// endpoints, through govue's own ApiClient so this app calls fetch in
// exactly one place, the same as every other request it makes.
//
// Every field the server reads or returns as bytes travels as base64
// (crypto.ts's own encodeBase64/decodeBase64, standard alphabet): these are
// JSON bodies, not URL components, so there is no reason to reach for the
// URL-safe alphabet the link's own fragment uses instead.

import type { ApiClient } from '@ostendorf-cloud/govue'

import { decodeBase64, encodeBase64, type Bytes } from './crypto'

export interface CreatedRequestLink {
  id: string
  expiresAt: Date
  maxSubmissionBytes: number
  /** maxConcurrentSubmissions is how many submissions this link holds waiting at once, not a lifetime total: opening it frees that many slots back up. */
  maxConcurrentSubmissions: number
}

interface createResponse {
  id: string
  expiresAt: string
  maxSubmissionBytes: number
  maxConcurrentSubmissions: number
}

/** createRequestLink stores a new request link's metadata and returns its id and its limits. */
export async function createRequestLink(
  client: ApiClient,
  ownerAuthHash: Bytes,
): Promise<CreatedRequestLink> {
  const resp = await client.post<createResponse>('/request-links', {
    ownerAuthHash: encodeBase64(ownerAuthHash),
  })
  return {
    id: resp.id,
    expiresAt: new Date(resp.expiresAt),
    maxSubmissionBytes: resp.maxSubmissionBytes,
    maxConcurrentSubmissions: resp.maxConcurrentSubmissions,
  }
}

export interface RequestLinkInfo {
  expiresAt: Date
  /** maxSubmissionBytes bounds the sealed payload, so slightly more than the secret itself. */
  maxSubmissionBytes: number
}

interface infoResponse {
  expiresAt: string
  maxSubmissionBytes: number
}

/** getRequestLinkInfo reads the limits a submitter needs before choosing what to send. */
export async function getRequestLinkInfo(client: ApiClient, id: string): Promise<RequestLinkInfo> {
  const resp = await client.get<infoResponse>(`/request-links/${encodeURIComponent(id)}`)
  return { expiresAt: new Date(resp.expiresAt), maxSubmissionBytes: resp.maxSubmissionBytes }
}

/** submitToRequestLink sends one sealed submission to the request link id names. */
export async function submitToRequestLink(
  client: ApiClient,
  id: string,
  payload: Bytes,
): Promise<void> {
  await client.post(`/request-links/${encodeURIComponent(id)}/submissions`, {
    payload: encodeBase64(payload),
  })
}

interface openResponse {
  submissions: string[]
}

/**
 * openRequestLink returns and removes every submission currently waiting
 * on the request link id names. ownerAuth is the value only the holder of
 * the matching private key can derive; see request-link-crypto.ts's
 * deriveOwnerAuth.
 */
export async function openRequestLink(
  client: ApiClient,
  id: string,
  ownerAuth: Bytes,
): Promise<Bytes[]> {
  const resp = await client.post<openResponse>(`/request-links/${encodeURIComponent(id)}/open`, {
    ownerAuth: encodeBase64(ownerAuth),
  })
  return resp.submissions.map((encoded) => decodeBase64(encoded))
}
