<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from 'vue'
import {
  GovueButton,
  GovueCard,
  GovueErrorState,
  GovueField,
  GovueInput,
  GovuePage,
  isApiError,
} from '@ostendorf-cloud/govue'

import { apiClient } from '../lib/api-client'
import { DecryptError, decryptSecret, type Bytes, type Content } from '../lib/crypto'
import { MissingKeyError, linkKeyFromFragment } from '../lib/secret-link'
import { openSecret } from '../lib/secrets-api'

const props = defineProps<{ id: string }>()

// ready: the key is valid and nothing was asked of the server yet. Opening
// takes the secret from the server for good, so it only happens on a click:
// a link preview or a crawler that fetches this page never opens it.
type Mode = 'ready' | 'opening' | 'passphrase' | 'revealed' | 'error'
const mode = ref<Mode>('ready')
const errorTitle = ref('')
const errorMessage = ref('')
const passphrase = ref('')
const passphraseError = ref('')
const content = ref<Content | null>(null)
const downloadUrl = ref('')
// True while a passphrase is being tried: PBKDF2 takes a moment and a second
// click must not start a second decrypt.
const busy = ref(false)

let linkKey: Bytes | null = null
// The payload is held in memory only while a passphrase is still needed: the
// server no longer has it, so a wrong passphrase must not cost the secret.
let payload: Bytes | null = null

function fail(title: string, message: string) {
  errorTitle.value = title
  errorMessage.value = message
  mode.value = 'error'
}

// Drops every trace of the secret from this page: the key and the payload
// buffers are zeroed like crypto.ts zeroes its own, the shown content and the
// download URL are released. Runs on unmount and when the page is hidden, so
// a page restored from the back/forward cache cannot show the secret again.
let disposed = false
function wipe() {
  disposed = true
  if (linkKey) linkKey.fill(0)
  linkKey = null
  if (payload) payload.fill(0)
  payload = null
  if (content.value?.type === 'file') content.value.data.fill(0)
  content.value = null
  passphrase.value = ''
  if (downloadUrl.value) URL.revokeObjectURL(downloadUrl.value)
  downloadUrl.value = ''
}

function onPageHide() {
  wipe()
  fail(
    'This page was left',
    'The secret is no longer held here. Open the link again if it was not opened yet. A secret that was already revealed cannot be shown again.',
  )
}

function onPageShow(event: PageTransitionEvent) {
  // A restored page is never trusted with what it held before.
  if (event.persisted) onPageHide()
}

onMounted(() => {
  window.addEventListener('pagehide', onPageHide)
  window.addEventListener('pageshow', onPageShow)
  try {
    linkKey = linkKeyFromFragment(window.location.hash.slice(1))
  } catch (err) {
    fail(
      'This link could not be opened',
      err instanceof MissingKeyError ? err.message : 'This link could not be opened.',
    )
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('pagehide', onPageHide)
  window.removeEventListener('pageshow', onPageShow)
  wipe()
})

async function reveal() {
  if (!linkKey || mode.value !== 'ready') return
  mode.value = 'opening'
  let fetched: Bytes
  try {
    fetched = await openSecret(apiClient, props.id)
  } catch (err) {
    if (isApiError(err) && err.status === 404) {
      fail(
        'This secret is not available',
        'The link is unknown, expired or was already opened. Nothing more can be said about which.',
      )
    } else {
      fail(
        'Could not reach the server',
        'If the link works again later, the secret is still there. If it says the link is gone, it was already opened.',
      )
    }
    return
  }
  if (disposed) {
    fetched.fill(0)
    return
  }
  payload = fetched
  await decrypt('')
}

async function decrypt(pass: string) {
  if (!linkKey || !payload) return
  try {
    const result = await decryptSecret(payload, linkKey, pass)
    if (disposed) return
    show(result)
  } catch (err) {
    if (disposed) return
    if (err instanceof DecryptError && err.code === 'passphrase_required') {
      mode.value = 'passphrase'
      return
    }
    if (err instanceof DecryptError && err.code === 'failed' && pass !== '') {
      // A wrong passphrase, or a damaged key that is still well formed: the
      // two cannot be told apart. The payload is still in memory, so it can
      // be tried again without the server.
      passphraseError.value = 'The passphrase or the link is wrong.'
      mode.value = 'passphrase'
      return
    }
    if (payload) payload.fill(0)
    payload = null
    fail(
      'The secret could not be decrypted',
      err instanceof DecryptError && err.code === 'unsupported'
        ? 'This secret uses a format this page does not know.'
        : 'The link is incomplete or damaged. The secret was already removed from the server.',
    )
  }
}

async function submitPassphrase() {
  if (busy.value) return
  if (passphrase.value === '') {
    passphraseError.value = 'Enter the passphrase first.'
    return
  }
  passphraseError.value = ''
  busy.value = true
  try {
    await decrypt(passphrase.value)
  } finally {
    busy.value = false
  }
}

// The key is of no use once the secret is shown, and the link is spent:
// the address bar and the history entry stop carrying it.
function show(result: Content) {
  if (payload) payload.fill(0)
  payload = null
  if (linkKey) linkKey.fill(0)
  linkKey = null
  passphrase.value = ''
  if (downloadUrl.value) URL.revokeObjectURL(downloadUrl.value)
  content.value = result
  if (result.type === 'file') {
    // Never rendered by the browser: a download with a neutral type.
    const blob = new Blob([result.data], { type: 'application/octet-stream' })
    downloadUrl.value = URL.createObjectURL(blob)
  }
  try {
    window.history.replaceState(null, '', window.location.pathname)
  } catch {
    // Not fatal: the secret is shown either way.
  }
  mode.value = 'revealed'
}

// A name from the sender is data: it only labels a download. Path separators
// and control characters become underscores, bidirectional controls (which
// can reorder the shown name) are dropped, and the length is capped.
const MAX_NAME = 120
function safeName(name: string): string {
  const cleaned = name
    .replace(/[\\/\u0000-\u001f\u007f]/g, '_')
    .replace(/[‪-‮⁦-⁩]/g, '')
    .trim()
  const capped = [...cleaned].slice(0, MAX_NAME).join('')
  return capped === '' || capped === '.' || capped === '..' ? 'secret' : capped
}
</script>

<template>
  <GovuePage>
    <GovueErrorState v-if="mode === 'error'" :title="errorTitle" :message="errorMessage" />

    <GovueCard v-else-if="mode === 'ready' || mode === 'opening'" title="Reveal a secret">
      <p class="text-text-muted">
        Someone sent you a secret. It can be opened exactly once: as soon as you reveal it, the
        server deletes it. Reveal it only when you are ready to read or save it.
      </p>
      <GovueButton variant="primary" :loading="mode === 'opening'" @click="reveal"
        >Reveal the secret</GovueButton
      >
    </GovueCard>

    <GovueCard v-else-if="mode === 'passphrase'" title="Passphrase needed">
      <p class="text-text-muted">
        This secret is protected by a passphrase. It is already removed from the server and is held
        only in this page: do not close or reload it before you have entered the passphrase.
      </p>
      <GovueField label="Passphrase" :error="passphraseError">
        <GovueInput v-model="passphrase" type="password" autocomplete="off" />
      </GovueField>
      <GovueButton variant="primary" :loading="busy" @click="submitPassphrase">Open</GovueButton>
    </GovueCard>

    <GovueCard v-else title="Your secret">
      <p class="text-text-muted">
        This link is now spent. Copy or save the secret: it cannot be shown again.
      </p>
      <pre
        v-if="content?.type === 'text'"
        class="overflow-x-auto whitespace-pre-wrap break-words rounded-md border border-border bg-surface-hover p-3 font-mono text-sm text-text"
        data-testid="revealed-text"
        >{{ content.text }}</pre>
      <p v-else-if="content?.type === 'file'" class="text-text">
        <a
          :href="downloadUrl"
          :download="safeName(content.name)"
          class="text-accent-text hover:underline"
          data-testid="revealed-file"
          >Download {{ safeName(content.name) }}</a
        >
      </p>
    </GovueCard>
  </GovuePage>
</template>
