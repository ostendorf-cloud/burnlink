<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
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
const fileInput = ref<HTMLInputElement | null>(null)
const passphrase = ref('')
const lifetime = ref('')
const notifyUrl = ref('')
const sending = ref(false)
const errorMessage = ref('')
const link = ref<{
  url: string
  expiresAt: Date
  protectedByPassphrase: boolean
  notified: boolean
} | null>(null)
const copied = ref(false)
const linkRegion = ref<HTMLElement | null>(null)

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

function tooLarge(limit: number): string {
  return `This secret is too large: the limit is ${limit} bytes after encryption.`
}

function messageFor(err: unknown): string {
  if (isApiError(err)) {
    if (err.status === 413) return 'This secret is too large to send.'
    if (err.status === 429) return 'Too many requests. Please wait a moment and try again.'
    if (err.status === 400 && notifyUrl.value.trim() !== '') {
      return 'The notification address was not accepted. Use a public https address on port 443, or leave it empty.'
    }
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
  // The ciphertext is never smaller than the file: refuse before reading it.
  if (file.value && config.value && file.value.size > config.value.maxCiphertextBytes) {
    errorMessage.value = tooLarge(config.value.maxCiphertextBytes)
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
      errorMessage.value = tooLarge(config.value.maxCiphertextBytes)
      return
    }
    const seconds = lifetime.value ? Number(lifetime.value) : undefined
    const stored = await storeSecret(apiClient, payload, seconds, notifyUrl.value.trim())
    link.value = {
      url: secretURL(window.location.origin, stored.id, linkKey),
      expiresAt: stored.expiresAt,
      protectedByPassphrase: passphrase.value.length > 0,
      notified: notifyUrl.value.trim() !== '',
    }
    notifyUrl.value = ''
    // Nothing of the secret stays in the form once the link exists. The file
    // input is reset too, or it would keep the file and its name, and
    // picking the same file again would fire no change event.
    text.value = ''
    file.value = null
    if (fileInput.value) fileInput.value.value = ''
    passphrase.value = ''
    // The link is below the form: a keyboard user lands on it, ready to copy.
    sending.value = false
    await nextTick()
    const field = linkRegion.value?.querySelector('input')
    field?.focus()
    field?.select()
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

    <form class="flex flex-col gap-4" @submit.prevent="send">
      <GovueField label="Secret text">
        <GovueTextarea
          v-model="text"
          :disabled="Boolean(file)"
          placeholder="Type the secret here"
        />
      </GovueField>
      <GovueField label="Or attach a file instead">
        <!-- A native control: it takes the id the field's label points at. -->
        <template #default="{ id, describedBy }">
          <input
            :id="id"
            ref="fileInput"
            type="file"
            :aria-describedby="describedBy"
            @change="onFileChange"
          />
        </template>
      </GovueField>
      <GovueField
        label="Passphrase (optional)"
        hint="A second factor. Send it through a different channel than the link. Choose a strong one: anyone holding the link can try guesses offline."
      >
        <GovueInput v-model="passphrase" type="password" autocomplete="off" />
      </GovueField>
      <GovueField v-if="lifetimeOptions.length > 0" label="Expires after">
        <GovueSelect v-model="lifetime" :options="lifetimeOptions" />
      </GovueField>
      <GovueField
        label="Notify me when it is opened (optional webhook URL)"
        hint="The server stores this address until the link is opened or expires, and so learns it, and who wants to know. When the link is opened, it sends one request there with the link's id and the time, never the secret. Delivery is tried a few times and is not guaranteed. Use a public https address on port 443."
      >
        <GovueInput v-model="notifyUrl" type="url" autocomplete="off" placeholder="https://" />
      </GovueField>

      <GovueButton variant="primary" type="submit" :loading="sending">Create link</GovueButton>
    </form>

    <div v-if="link" ref="linkRegion" class="flex flex-col gap-2" data-testid="secret-link">
      <p class="text-text">
        Send this link to one person. It works exactly once, until
        {{ link.expiresAt.toLocaleString() }}. Whoever opens it first gets the secret.
      </p>
      <p v-if="link.protectedByPassphrase" class="text-text-muted">
        The recipient also needs the passphrase. Send it through a different channel.
      </p>
      <p v-if="link.notified" class="text-text-muted">
        The server will call your webhook once when the link is opened, if it can.
      </p>
      <GovueInput :model-value="link.url" readonly aria-label="Secret link" />
      <GovueButton variant="secondary" @click="copy">{{
        copied ? 'Copied' : 'Copy link'
      }}</GovueButton>
    </div>
  </GovueCard>
</template>
