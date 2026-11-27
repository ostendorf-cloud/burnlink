<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  GovueButton,
  GovueCard,
  GovueEmptyState,
  GovueErrorState,
  GovueField,
  GovuePage,
  GovueSkeleton,
  GovueTextarea,
} from '@ostendorf-cloud/govue'

import { apiClient } from '../lib/api-client'
import type { Bytes, Content } from '../lib/crypto'
import { getRequestLinkInfo, openRequestLink, submitToRequestLink } from '../lib/request-link-api'
import { safeName } from '../lib/safe-name'
import { MissingFragmentError, importOwnerPublicKeyFromFragment } from '../lib/request-link'
import {
  UnsupportedBrowserError,
  assertX25519Supported,
  deriveOwnerAuth,
  openSubmission,
  sealSubmission,
} from '../lib/request-link-crypto'
import { hasOwnerKey, loadOwnerKey } from '../lib/request-link-keys'
import { appendSubmissions, loadSubmissions } from '../lib/request-link-submissions'

const props = defineProps<{ id: string }>()

type Mode = 'loading' | 'error' | 'submit' | 'submitted' | 'owner'
const mode = ref<Mode>('loading')
const errorMessage = ref('')
const ownerPublicKeyRaw = ref<Bytes | null>(null)
const submissions = ref<Content[]>([])
// lossNotice is set when a submission arrived and was already removed
// from the server, but could not be saved in this browser: it is gone,
// and the owner is told so plainly instead of the list quietly staying
// the same size. It never hides submissions.value, which keeps showing
// whatever was durably saved before and after the loss.
const lossNotice = ref('')
// checkFailedNotice is set when the round trip to the server itself
// failed, after this browser's own durable copy already loaded and
// rendered: nothing arrived, nothing was removed from the server, and
// nothing already saved is at risk. It is kept apart from lossNotice
// because the two mean opposite things, and an owner must never read a
// transient network failure as submissions being destroyed.
const checkFailedNotice = ref('')
const text = ref('')
const file = ref<File | null>(null)
const submitting = ref(false)
const opening = ref(false)
// maxSubmissionBytes is the sealed size limit the link reports, shown to a
// submitter before a file is chosen. It stays null when the lookup failed:
// the form still works and the server enforces the limit either way.
const maxSubmissionBytes = ref<number | null>(null)

function formatBytes(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1).replace(/\.0$/, '')} MiB`
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1).replace(/\.0$/, '')} KiB`
  return `${bytes} bytes`
}

// saveFile hands a received file to the browser's own save dialog. The data
// is already in this browser's storage, so nothing here touches the network.
// The type is neutral, so the browser never renders what a stranger sent.
function saveFile(submission: Extract<Content, { type: 'file' }>) {
  const url = URL.createObjectURL(new Blob([submission.data], { type: 'application/octet-stream' }))
  const link = document.createElement('a')
  link.href = url
  link.download = safeName(submission.name)
  link.click()
  // Some browsers cancel the download when the URL is revoked right after the click.
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

function messageFor(err: unknown): string {
  if (err instanceof MissingFragmentError || err instanceof UnsupportedBrowserError) {
    return err.message
  }
  return 'This request link could not be opened.'
}

function lossMessage(count: number): string {
  const single = count === 1
  const noun = single ? 'submission' : 'submissions'
  const was = single ? 'was' : 'were'
  const pronoun = single ? 'It' : 'They'
  return (
    `${count} ${noun} arrived and ${was} already removed from the server, but this browser ` +
    `could not save ${single ? 'it' : 'them'}. ${pronoun} cannot be recovered.`
  )
}

/**
 * openAsOwner shows what this browser already saved for the link before
 * doing anything else, then asks the server for anything new. The server's
 * own store is read-once: whatever open() returns is already gone from it
 * by the time this function sees it, so a newly opened submission is
 * written into this browser's own durable storage, and only then added to
 * submissions.value, before anything new is rendered. If that write fails,
 * the submission is not shown as received: it is reported as lost instead,
 * because the server copy is already gone and there is nowhere left to
 * retry the read.
 */
async function openAsOwner() {
  opening.value = true
  lossNotice.value = ''
  checkFailedNotice.value = ''
  try {
    const keyPair = await loadOwnerKey(props.id)
    if (!keyPair) {
      errorMessage.value = 'This browser no longer holds the key to this request link.'
      mode.value = 'error'
      return
    }

    // Shown first, from this browser's own durable copy, independent of
    // whether the server round trip below succeeds: a reload must show
    // what was already taken even if checking for anything new fails.
    submissions.value = await loadSubmissions(props.id)
    mode.value = 'owner'

    const ownerAuth = await deriveOwnerAuth(keyPair.privateKey, keyPair.publicKey)
    const payloads = await openRequestLink(apiClient, props.id, ownerAuth)
    const opened: Content[] = []
    for (const payload of payloads) {
      try {
        opened.push(await openSubmission(payload, keyPair.privateKey, keyPair.publicKeyRaw))
      } catch {
        // A submission that fails to open is left out rather than shown as
        // broken: it cannot be anything this owner's key was meant to open.
      }
    }
    if (opened.length > 0) {
      try {
        submissions.value = await appendSubmissions(props.id, opened)
      } catch {
        // Every payload in payloads was already GetDel'd from the server
        // above, not only the ones that decrypted into opened: a failed
        // write here loses all of them, so the count names payloads.length
        // rather than opened.length, or it would understate the loss by
        // the number that failed to decrypt.
        lossNotice.value = lossMessage(payloads.length)
      }
    }
  } catch (err) {
    // Nothing durable was shown yet: loading this browser's own saved
    // submissions, or reading the owner's key, failed before mode could
    // switch to 'owner'. That is a full failure, same as before this
    // function started persisting anything.
    if (mode.value === 'owner') {
      // The durable load above already succeeded and is on screen: this
      // failure is the server round trip or the owner-auth derivation
      // after it, neither of which has removed or lost a submission.
      // Kept out of lossNotice on purpose, so a transient network failure
      // is never read as data destroyed.
      checkFailedNotice.value =
        'Nothing was lost. What was already saved is still shown below; try checking again.'
    } else {
      errorMessage.value = messageFor(err)
      mode.value = 'error'
    }
  } finally {
    opening.value = false
  }
}

onMounted(async () => {
  if (await hasOwnerKey(props.id)) {
    await openAsOwner()
    return
  }
  try {
    await assertX25519Supported()
    const fragment = window.location.hash.slice(1)
    const { publicKeyRaw } = await importOwnerPublicKeyFromFragment(fragment)
    ownerPublicKeyRaw.value = publicKeyRaw
    try {
      maxSubmissionBytes.value = (await getRequestLinkInfo(apiClient, props.id)).maxSubmissionBytes
    } catch {
      // Not fatal: see maxSubmissionBytes.
    }
    mode.value = 'submit'
  } catch (err) {
    errorMessage.value = messageFor(err)
    mode.value = 'error'
  }
})

async function submit() {
  if (!ownerPublicKeyRaw.value) {
    return
  }
  errorMessage.value = ''
  submitting.value = true
  try {
    const content = file.value
      ? {
          type: 'file' as const,
          name: file.value.name,
          mime: file.value.type,
          data: new Uint8Array(await file.value.arrayBuffer()),
        }
      : { type: 'text' as const, text: text.value }
    const payload = await sealSubmission(content, ownerPublicKeyRaw.value)
    await submitToRequestLink(apiClient, props.id, payload)
    mode.value = 'submitted'
  } catch (err) {
    errorMessage.value = messageFor(err)
  } finally {
    submitting.value = false
  }
}

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  file.value = input.files?.[0] ?? null
}
</script>

<template>
  <!-- GovuePage is the one main landmark, the skip link's target #main, in every mode. -->
  <GovuePage>
    <GovueCard v-if="mode === 'loading'" title="Request link">
      <GovueSkeleton :lines="3" />
    </GovueCard>

    <GovueErrorState
      v-else-if="mode === 'error'"
      title="This request link could not be opened"
      :message="errorMessage"
    />

    <GovueCard v-else-if="mode === 'submit'" title="Send a secret">
      <p class="text-text-muted">
        This secret is sealed in your browser before it ever leaves it. The server only ever sees
        the encrypted result, and nothing here identifies you to the owner.
      </p>
      <p v-if="maxSubmissionBytes !== null" class="text-text-muted" data-testid="size-limit">
        The sealed secret, text or file, may be at most {{ formatBytes(maxSubmissionBytes) }}.
        Sealing adds a little overhead, so a file just under this size may be refused.
      </p>
      <GovueErrorState
        v-if="errorMessage"
        title="Could not send this secret"
        :message="errorMessage"
      />
      <GovueField label="Secret text">
        <GovueTextarea
          v-model="text"
          :disabled="Boolean(file)"
          placeholder="Type the secret here"
        />
      </GovueField>
      <GovueField label="Or attach a file instead">
        <input type="file" @change="onFileChange" />
      </GovueField>
      <GovueButton variant="primary" :loading="submitting" @click="submit">Send</GovueButton>
    </GovueCard>

    <GovueCard v-else-if="mode === 'submitted'" title="Sent">
      <p class="text-text">
        Sealed and sent. Only the owner's own browser can open it; this page cannot show you whether
        or when that happens.
      </p>
    </GovueCard>

    <GovueCard v-else title="Submissions">
      <GovueButton variant="secondary" :loading="opening" @click="openAsOwner"
        >Check again</GovueButton
      >
      <GovueErrorState
        v-if="lossNotice"
        title="Some submissions could not be saved"
        :message="lossNotice"
      />
      <GovueErrorState
        v-if="checkFailedNotice"
        title="Could not check for new submissions"
        :message="checkFailedNotice"
      />
      <GovueEmptyState
        v-if="submissions.length === 0"
        title="Nothing waiting"
        description="No submission has arrived yet. Checking again looks for anything new."
      />
      <ul v-else class="flex flex-col gap-3">
        <li
          v-for="(submission, index) in submissions"
          :key="index"
          class="rounded-md border border-border p-3"
        >
          <p v-if="submission.type === 'text'" class="whitespace-pre-wrap text-text">
            {{ submission.text }}
          </p>
          <div v-else class="flex items-center justify-between gap-3">
            <p class="text-text">{{ submission.name }} ({{ submission.mime || 'unknown type' }})</p>
            <GovueButton variant="secondary" @click="saveFile(submission)"
              >Save {{ safeName(submission.name) }}</GovueButton
            >
          </div>
        </li>
      </ul>
    </GovueCard>
  </GovuePage>
</template>
