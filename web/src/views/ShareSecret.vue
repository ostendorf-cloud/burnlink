<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  GovueButton,
  GovueCard,
  GovueErrorState,
  GovueField,
  GovueInput,
  GovueSelect,
  GovueTextarea,
  isApiError,
} from '@ostendorf-cloud/govue'

import { apiClient } from '../lib/api-client'
import { encryptSecret, generateLinkKey, type ContentInput } from '../lib/crypto'
import { secretURL } from '../lib/secret-link'
import { getConfig, storeSecret, type SecretConfig } from '../lib/secrets-api'

const config = ref<SecretConfig | null>(null)
const text = ref('')
const file = ref<File | null>(null)
const passphrase = ref('')
const lifetime = ref('')
const sending = ref(false)
const errorMessage = ref('')
const link = ref<{ url: string; expiresAt: Date; protectedByPassphrase: boolean } | null>(null)
const copied = ref(false)

// The page asks the server for its limits once. Without them it still sends,
// with the server's own default lifetime, and the server enforces its limits.
onMounted(async () => {
  try {
    config.value = await getConfig(apiClient)
    lifetime.value = String(config.value.lifetime.defaultSeconds)
  } catch {
    config.value = null
  }
})

const PRESETS: [number, string][] = [
  [300, '5 minutes'],
  [3600, '1 hour'],
  [86400, '24 hours'],
  [604800, '7 days'],
  [2592000, '30 days'],
]

function describe(seconds: number): string {
  const preset = PRESETS.find(([s]) => s === seconds)
  if (preset) return preset[1]
  if (seconds % 86400 === 0) return `${seconds / 86400} days`
  if (seconds % 3600 === 0) return `${seconds / 3600} hours`
  if (seconds % 60 === 0) return `${seconds / 60} minutes`
  return `${seconds} seconds`
}

const lifetimeOptions = computed(() => {
  const limits = config.value?.lifetime
  if (!limits) return []
  const seconds = new Set<number>([limits.defaultSeconds])
  for (const [s] of PRESETS) {
    if (s >= limits.minSeconds && s <= limits.maxSeconds) seconds.add(s)
  }
  return [...seconds].sort((a, b) => a - b).map((s) => ({ value: String(s), label: describe(s) }))
})

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  file.value = input.files?.[0] ?? null
}

function messageFor(err: unknown): string {
  if (isApiError(err)) {
    if (err.status === 413) return 'This secret is too large to send.'
    if (err.status === 429) return 'Too many requests. Please wait a moment and try again.'
  }
  return 'Could not send this secret. Please try again.'
}

async function send() {
  errorMessage.value = ''
  link.value = null
  copied.value = false
  if (!file.value && text.value === '') {
    errorMessage.value = 'Enter a secret text or attach a file first.'
    return
  }
  sending.value = true
  try {
    const content: ContentInput = file.value
      ? {
          type: 'file',
          name: file.value.name,
          mime: file.value.type,
          data: new Uint8Array(await file.value.arrayBuffer()),
        }
      : { type: 'text', text: text.value }
    // The key is made here and only ever leaves this function as the
    // fragment of the link shown below: it is never sent to the server.
    const linkKey = generateLinkKey()
    const payload = await encryptSecret(content, linkKey, passphrase.value)
    if (config.value && payload.length > config.value.maxCiphertextBytes) {
      errorMessage.value = `This secret is too large: the limit is ${config.value.maxCiphertextBytes} bytes after encryption.`
      return
    }
    const seconds = lifetime.value ? Number(lifetime.value) : undefined
    const stored = await storeSecret(apiClient, payload, seconds)
    link.value = {
      url: secretURL(window.location.origin, stored.id, linkKey),
      expiresAt: stored.expiresAt,
      protectedByPassphrase: passphrase.value.length > 0,
    }
    // Nothing of the secret stays in the form once the link exists.
    text.value = ''
    file.value = null
    passphrase.value = ''
  } catch (err) {
    errorMessage.value = messageFor(err)
  } finally {
    sending.value = false
  }
}

async function copy() {
  if (!link.value) return
  try {
    await navigator.clipboard.writeText(link.value.url)
    copied.value = true
  } catch {
    copied.value = false
  }
}
</script>

<template>
  <GovueCard title="Share a secret">
    <p class="text-text-muted">
      The secret is encrypted in your browser before it leaves it. The server stores only the
      encrypted result and hands it out once. The key is part of the link after the #, which your
      browser never sends to the server.
    </p>

    <GovueErrorState v-if="errorMessage" title="Could not share" :message="errorMessage" />

    <GovueField label="Secret text">
      <GovueTextarea v-model="text" :disabled="Boolean(file)" placeholder="Type the secret here" />
    </GovueField>
    <GovueField label="Or attach a file instead">
      <input type="file" @change="onFileChange" />
    </GovueField>
    <GovueField
      label="Passphrase (optional)"
      hint="A second factor. Send it through a different channel than the link."
    >
      <GovueInput v-model="passphrase" type="password" autocomplete="new-password" />
    </GovueField>
    <GovueField v-if="lifetimeOptions.length > 0" label="Expires after">
      <GovueSelect v-model="lifetime" :options="lifetimeOptions" />
    </GovueField>

    <GovueButton variant="primary" :loading="sending" @click="send">Create link</GovueButton>

    <div v-if="link" class="flex flex-col gap-2" data-testid="secret-link">
      <p class="text-text">
        Send this link to one person. It works exactly once, until
        {{ link.expiresAt.toLocaleString() }}. Whoever opens it first gets the secret.
      </p>
      <p v-if="link.protectedByPassphrase" class="text-text-muted">
        The recipient also needs the passphrase. Send it through a different channel.
      </p>
      <GovueInput :model-value="link.url" readonly aria-label="Secret link" />
      <GovueButton variant="secondary" @click="copy">{{
        copied ? 'Copied' : 'Copy link'
      }}</GovueButton>
    </div>
  </GovueCard>
</template>
