// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// apiClient is the one place this app's components reach the server
// through, govue's own createClient with every default: no session cookie
// and no CSRF token are in play yet, and the base path matches
// internal/webapp/requestlink's own routes under /api/v1. No key is ever
// sent. Two values derived from the owner's keypair are: ownerAuthHash, a
// SHA-256 digest, and ownerAuth, an HKDF output. Neither reveals a key, since
// both come from a one way function.
import { createClient } from '@ostendorf-cloud/govue'

export const apiClient = createClient()
