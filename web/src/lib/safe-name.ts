// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

// A name from the sender is data: it only labels a download. Path separators
// and control characters become underscores, bidirectional controls (which
// can reorder the shown name) are dropped, and the length is capped.
const MAX_NAME = 120

export function safeName(name: string): string {
  const cleaned = name
    .replace(/[\\/\u0000-\u001f\u007f]/g, '_')
    .replace(/[‪-‮⁦-⁩]/g, '')
    .trim()
  const capped = [...cleaned].slice(0, MAX_NAME).join('')
  return capped === '' || capped === '.' || capped === '..' ? 'secret' : capped
}
