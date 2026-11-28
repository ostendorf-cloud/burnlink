<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { nextTick, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import {
  GovueButton,
  GovueCard,
  GovueErrorState,
  GovueField,
  GovueInput,
  GovuePage,
  isApiError,
} from '@ostendorf-cloud/govue'

import { apiClient, headClient } from '../lib/api-client'
import { DecryptError, decryptSecret, type Bytes, type Content } from '../lib/crypto'
import { MissingKeyError, linkKeyFromFragment } from '../lib/secret-link'
import { safeName } from '../lib/safe-name'
import { checkSecret, openSecret } from '../lib/secrets-api'

const props = defineProps<{ id: string }>()

// checking: the key is valid and the server is asked whether the secret is
// still there. That check takes nothing. ready: the secret is waiting.
// Opening takes it from the server for good, so it only happens on a click:
// a link preview or a crawler that fetches this page never opens it.
type Mode = 'checking' | 'ready' | 'opening' | 'passphrase' | 'revealed' | 'error'
const mode = ref<Mode>('checking')
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

const region = ref<HTMLElement | null>(null)
// Set when the visitor caused the next view, so focus follows it. The first
// view on load leaves focus alone, where the skip link expects it.
let moveFocus = false

function fail(title: string, message: string) {
  errorTitle.value = title
  errorMessage.value = message
  mode.value = 'error'
}

// A view replaces the one the visitor just used, and the control they pressed
// goes with it. Focus moves to the new view's heading, or to the passphrase
// field, so a keyboard or screen reader user is not left on nothing.
function focusView() {
  const input = mode.value === 'passphrase' ? region.value?.querySelector('input') : null
  if (input) {
    input.focus()
    return
  }
  const heading = region.value?.querySelector<HTMLElement>('h1, h2, h3')
  if (heading) {
    heading.setAttribute('tabindex', '-1')
    heading.focus()
  }
}

watch(mode, async (next) => {
  if (!moveFocus || next === 'checking' || next === 'opening') return
  moveFocus = false
  await nextTick()
  focusView()
})

// Drops every trace of the secret from this page: the key and the payload
// buffers are zeroed like crypto.ts zeroes its own, the shown content and the
// download URL are released. Runs on unmount and when the page is hidden, so
// a page restored from the back/forward cache cannot show the secret again.
// The generation tells a call that was in flight when it ran to stop.
let generation = 0
function wipe() {
  generation++
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

// Reads the key and asks the server whether the secret is still there. The
// check never takes it, and a link with no usable key never reaches the server.
async function start() {
  const current = generation
  mode.value = 'checking'
  if (linkKey) linkKey.fill(0)
  linkKey = null
  try {
    linkKey = linkKeyFromFragment(window.location.hash.slice(1))
  } catch (err) {
    fail(
      'This link could not be opened',
      err instanceof MissingKeyError ? err.message : 'This link could not be opened.',
    )
    return
  }
  try {
    await checkSecret(headClient, props.id)
  } catch (err) {
    if (current !== generation) return
    if (isApiError(err) && err.status === 404) {
      // Nothing left to open, so the key has no use either.
      if (linkKey) linkKey.fill(0)
      linkKey = null
      fail(
        'This secret is not available',
        'The link is unknown, expired or was already opened. Nothing more can be said about which.',
      )
    } else if (isApiError(err) && err.status === 429) {
      fail('Too many requests', 'Please wait a moment and try again. The secret was not opened.')
    } else {
      fail(
        'Could not reach the server',
        'The secret was not opened. Try again when the connection works.',
      )
    }
    return
  }
  if (current !== generation) return
  mode.value = 'ready'
}

function retry() {
  moveFocus = true
  void start()
}

onMounted(() => {
  window.addEventListener('pagehide', onPageHide)
  window.addEventListener('pageshow', onPageShow)
  void start()
})

onBeforeUnmount(() => {
  window.removeEventListener('pagehide', onPageHide)
  window.removeEventListener('pageshow', onPageShow)
  wipe()
})

async function reveal() {
  if (!linkKey || mode.value !== 'ready') return
  const current = generation
  moveFocus = true
  mode.value = 'opening'
  let fetched: Bytes
  try {
    fetched = await openSecret(apiClient, props.id)
  } catch (err) {
    if (current !== generation) return
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
  if (current !== generation) {
    fetched.fill(0)
    return
  }
  payload = fetched
  await decrypt('')
}

async function decrypt(pass: string) {
  if (!linkKey || !payload) return
  const current = generation
  try {
    const result = await decryptSecret(payload, linkKey, pass)
    if (current !== generation) return
    show(result)
  } catch (err) {
    if (current !== generation) return
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
      await nextTick()
      focusView()
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
</script>

<template>
  <GovuePage>
    <div ref="region" class="flex flex-col gap-4">
      <GovueErrorState
        v-if="mode === 'error'"
        :title="errorTitle"
        :message="errorMessage"
        retry-label="Check the link again"
        @retry="retry"
      />

      <GovueCard v-else-if="mode === 'checking'" title="Checking the link">
        <p class="text-text-muted" role="status">
          Asking the server whether the secret is still there. This does not open it.
        </p>
      </GovueCard>

      <GovueCard v-else-if="mode === 'ready' || mode === 'opening'" title="A secret is waiting">
        <p class="text-text-muted">
          Someone sent you a secret, and it has not been opened. It can be opened exactly once: as
          soon as you reveal it, the server deletes it. Reveal it only when you are ready to read or
          save it.
        </p>
        <GovueButton variant="primary" :loading="mode === 'opening'" @click="reveal"
          >Reveal the secret</GovueButton
        >
      </GovueCard>

      <GovueCard v-else-if="mode === 'passphrase'" title="Passphrase needed">
        <p class="text-text-muted">
          This secret is protected by a passphrase. It is already removed from the server and is
          held only in this page: do not close or reload it before you have entered the passphrase.
        </p>
        <form class="flex flex-col gap-4" @submit.prevent="submitPassphrase">
          <GovueField label="Passphrase" :error="passphraseError">
            <GovueInput v-model="passphrase" type="password" autocomplete="off" />
          </GovueField>
          <GovueButton variant="primary" type="submit" :loading="busy">Open</GovueButton>
        </form>
      </GovueCard>

      <GovueCard v-else title="Your secret">
        <p class="text-text-muted">
          This link is now spent. Copy or save the secret: it cannot be shown again.
        </p>
        <pre
          v-if="content?.type === 'text'"
          role="region"
          aria-label="Secret text"
          tabindex="0"
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
    </div>
  </GovuePage>
</template>
