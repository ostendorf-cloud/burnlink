// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// apiClient is the one place this app's components reach the server
// through, govue's own createClient with every default: no session cookie
// and no CSRF token are in play yet, nothing this app sends is ever key
// material, and the base path matches internal/webapp/requestlink's own
// routes under /api/v1.
import { createClient } from '@ostendorf-cloud/govue'

export const apiClient = createClient()
