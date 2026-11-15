<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { ref } from 'vue'
import { GovueButton, GovueCard, GovueErrorState, GovueInput } from '@ostendorf-cloud/govue'

import { apiClient } from '../lib/api-client'
import { createRequestLink } from '../lib/request-link-api'
import { requestLinkURL } from '../lib/request-link'
import {
  UnsupportedBrowserError,
  deriveOwnerAuth,
  generateOwnerKeyPair,
} from '../lib/request-link-crypto'
import { requestPersistentStorage, saveOwnerKey } from '../lib/request-link-keys'

interface CreatedLink {
  url: string
  expiresAt: Date
  maxConcurrentSubmissions: number
  maxSubmissionBytes: number
}

const creating = ref(false)
const errorMessage = ref('')
const link = ref<CreatedLink | null>(null)

async function create() {
  errorMessage.value = ''
  creating.value = true
  try {
    const keyPair = await generateOwnerKeyPair()
    const ownerAuth = await deriveOwnerAuth(keyPair.privateKey, keyPair.publicKey)
    const ownerAuthHash = new Uint8Array(
      await globalThis.crypto.subtle.digest('SHA-256', ownerAuth),
    )
    const created = await createRequestLink(apiClient, ownerAuthHash)

    await saveOwnerKey(created.id, keyPair)
    await requestPersistentStorage()

    link.value = {
      url: requestLinkURL(window.location.origin, created.id, keyPair.publicKeyRaw),
      expiresAt: created.expiresAt,
      maxConcurrentSubmissions: created.maxConcurrentSubmissions,
      maxSubmissionBytes: created.maxSubmissionBytes,
    }
  } catch (err) {
    errorMessage.value =
      err instanceof UnsupportedBrowserError
        ? err.message
        : 'Could not create a request link. Please try again.'
  } finally {
    creating.value = false
  }
}
</script>

<template>
  <GovueCard title="Receive a secret through a request link">
    <p class="text-text-muted">
      Publish this link. Anyone holding it can send you a secret back, sealed in their own browser
      to a key only this browser holds. The server stores what they send without ever being able to
      read it.
    </p>

    <p data-testid="loss-notice" class="font-medium text-text">
      Before you publish: the key that opens a submission exists only in this browser. Clearing this
      site's data, opening this link in another browser or device, using a private window, or the
      browser dropping storage it wrote all destroy every submission ever made to this link,
      permanently. The server never holds a copy of the key and cannot help recover it.
    </p>

    <GovueErrorState
      v-if="errorMessage"
      title="Could not create a request link"
      :message="errorMessage"
    />

    <GovueButton variant="primary" :loading="creating" @click="create">
      Create a request link
    </GovueButton>

    <div v-if="link" class="flex flex-col gap-2" data-testid="created-link">
      <p class="text-text">
        Share this link with whoever should be able to send you a secret. It holds up to
        {{ link.maxConcurrentSubmissions }} submissions waiting at once, each up to
        {{ link.maxSubmissionBytes }} bytes, until {{ link.expiresAt.toLocaleString() }}. Opening it
        frees those slots again, so more can still arrive afterwards.
      </p>
      <GovueInput :model-value="link.url" readonly />
    </div>
  </GovueCard>
</template>
