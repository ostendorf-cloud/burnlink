<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { GovueCard, GovuePage } from '@ostendorf-cloud/govue'

import { PBKDF2_ITERATIONS, VERSION } from '../lib/crypto'

// The numbers come from the format itself rather than from the text, so a
// change to crypto.ts cannot leave this page claiming the old ones.
const iterations = PBKDF2_ITERATIONS.toLocaleString('en-US').replace(/,/g, ' ')
</script>

<template>
  <GovuePage
    title="How a secret stays secret"
    lead="What the server holds, what it cannot hold, and where this stops helping."
  >
    <GovueCard as="section" title="What is running today">
      <div class="flex flex-col gap-3 text-base text-text-muted" data-testid="status">
        <p>
          This page describes a design, and says so where a part of it is not running yet. The
          encryption of an ordinary secret exists in the repository as a library with tests. It is
          not part of any page you can use yet. The store that keeps a secret for one read is not
          connected to the running server, and the page that sends an ordinary secret is not built.
        </p>
        <p>
          The request link is a link you publish so that someone can send you a secret back. Its
          pages and its server endpoints are written, but the running server does not serve those
          endpoints yet, so it cannot be used today.
        </p>
      </div>
    </GovueCard>

    <GovueCard as="section" title="What the server has">
      <dl class="flex flex-col gap-4">
        <div class="flex flex-col gap-1">
          <dt class="text-sm font-medium text-text">It stores</dt>
          <dd class="text-base text-text-muted">
            The encrypted payload exactly as it arrived, a random id from 16 random bytes, and an
            expiry. A request link expires after 7 days and takes payloads up to 1 MiB, both
            defaults that may change. The lifetime of an ordinary secret is not fixed yet.
          </dd>
        </div>
        <div class="flex flex-col gap-1">
          <dt class="text-sm font-medium text-text">For a request link it also holds</dt>
          <dd class="text-base text-text-muted">
            The link's limits: how many submissions it holds waiting at once, 50 by default, and the
            size limit. A SHA-256 hash of a value only the owner's browser can derive, which tells
            the owner's open call apart from everyone else's. The server never holds the public key
            or the private key.
          </dd>
        </div>
        <div class="flex flex-col gap-1">
          <dt class="text-sm font-medium text-text">It sees</dt>
          <dd class="text-base text-text-muted">
            The address a request arrives from. Submissions to a request link are rate limited per
            link and per address, and the address is also in the access log. When the owner opens
            the link, the browser sends the value that hash is checked against.
          </dd>
        </div>
        <div class="flex flex-col gap-1">
          <dt class="text-sm font-medium text-text">It never receives</dt>
          <dd class="text-base text-text-muted">
            The key, the passphrase, the text, the file or its name. It does not decode the payload
            and has nothing to decode it with.
          </dd>
        </div>
      </dl>
    </GovueCard>

    <GovueCard as="section" title="The link carries the key">
      <div class="flex flex-col gap-4 text-base text-text-muted">
        <p class="overflow-x-auto font-mono text-sm text-text">
          https://burnlink.de/s/<span class="text-accent-text">&lt;id&gt;</span>#<span
            class="text-accent-text"
            >&lt;key&gt;</span
          >
        </p>
        <p class="text-sm">
          An example of the planned shape of a send link. This route does not exist yet.
        </p>

        <ul class="flex list-disc flex-col gap-2 pl-5">
          <li>
            The key is 32 random bytes from the browser's own generator, written after the
            <code class="font-mono text-text">#</code>.
          </li>
          <li>
            A browser never sends the part after the
            <code class="font-mono text-text">#</code>, the key fragment, to a server. The half of
            the link that can decrypt the secret therefore never travels to burnlink.
          </li>
          <li>Whoever holds the whole link can read the secret. Send it to one person.</li>
        </ul>
      </div>
    </GovueCard>

    <GovueCard as="section" title="The encryption">
      <div class="flex flex-col gap-4">
        <p class="text-base text-text-muted">
          Done in the browser with WebCrypto, before anything is uploaded. The payload is one blob
          of bytes:
        </p>

        <pre
          class="overflow-x-auto rounded-md border border-border bg-surface-hover p-3 font-mono text-xs text-text"
        >
version │ flags │ salt (16, only with a passphrase) │ iv (12) │ ciphertext + tag (16)</pre>

        <dl class="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-[auto_1fr]">
          <dt class="text-sm font-medium text-text">Cipher</dt>
          <dd class="text-base text-text-muted">AES-256-GCM, 12 byte iv, 16 byte tag</dd>

          <dt class="text-sm font-medium text-text">Key</dt>
          <dd class="text-base text-text-muted">HKDF-SHA-256 over the key from the link</dd>

          <dt class="text-sm font-medium text-text">Format</dt>
          <dd class="text-base text-text-muted">
            Version {{ VERSION }}. A change to the layout is a new version, not an edit.
          </dd>
        </dl>

        <ul class="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
          <li>
            Everything before the ciphertext is authenticated along with it, so flipping a flag or
            swapping the salt breaks decryption instead of quietly changing the result.
          </li>
          <li>
            The plaintext is padded to a multiple of 256 bytes, so a four character password and a
            forty character one are stored at the same size.
          </li>
        </ul>
      </div>
    </GovueCard>

    <GovueCard as="section" title="A passphrase on top">
      <ul class="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
        <li>
          Optional, and a genuine second factor: the receiver needs it in addition to the link, and
          the server never had it either.
        </li>
        <li>PBKDF2-SHA-256 with {{ iterations }} iterations and a 16 byte salt.</li>
        <li>
          Its output is joined to the key from the link before the AES key is derived, so neither
          half on its own opens the secret.
        </li>
        <li>
          The iteration count belongs to the payload version and is never read out of the payload,
          so a tampered payload cannot ask for a cheaper one.
        </li>
        <li>Send it through a different channel than the link, or it is not a second factor.</li>
      </ul>
    </GovueCard>

    <GovueCard as="section" title="One link, one read">
      <ul class="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
        <li>
          The design: revealing takes the payload and deletes it in the same step, one read, so if
          two people open at the same moment, exactly one of them gets it. The store contract is
          written for that, and the request link's open endpoint already uses it.
        </li>
        <li>
          Not running yet: the store behind the running server, and the endpoints that hand out an
          ordinary secret. Until then no secret is kept for one read.
        </li>
        <li>
          Meant to be the same answer for an unknown, expired, already opened or malformed link.
          Today the request link's open endpoint answers an unknown id, a wrong owner proof and an
          expired link alike. Its other endpoints still tell a full or oversized submission apart.
        </li>
      </ul>
    </GovueCard>

    <GovueCard as="section" title="A request link keeps its key in one browser">
      <ul class="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
        <li>
          The owner's public key sits in the key fragment of the link, so the server never sees it.
          A stranger seals a secret to it in their own browser.
        </li>
        <li>
          The private key stays in this browser as a key it cannot export. There is no copy on the
          server and no second link.
        </li>
        <li>
          Clearing site data, another browser or device, or a private window destroys every
          submission to that link, permanently. Nobody can recover them.
        </li>
        <li>
          A submitter cannot check that the key in the link belongs to the owner. If someone
          replaces the fragment while the link travels, for example in a chat or a mail, neither
          side can see it.
        </li>
        <li>
          Submissions are not authenticated. Anyone holding the link can submit, and the owner
          cannot tell who sent a submission or tell two senders apart beyond the order they arrive.
        </li>
      </ul>
    </GovueCard>

    <GovueCard as="section" title="What is counted">
      <div class="flex flex-col gap-4 text-base text-text-muted" data-testid="counting">
        <p>
          If the operator has turned it on, the server counts page views and reports them to
          Umami, a statistics tool, after the page was served. Nothing runs in your browser and no
          cookie is set.
        </p>
        <ul class="flex list-disc flex-col gap-2 pl-5">
          <li>
            Counted: a visit to a page, as the name of the page only, for example
            <code class="font-mono text-text">/security</code> or
            <code class="font-mono text-text">/r/&#123;id&#125;</code>. The second is one entry for
            every link, not one per link.
          </li>
          <li>
            Also sent with it: the site's own host name, the first language your browser asks for,
            your browser and system as its user agent, the site that referred you (host only, no
            path), and your address with its last part removed: the first three of four numbers for
            IPv4, the first 48 bits for IPv6. Umami derives country and region from it.
          </li>
          <li>
            Not counted: the id of a link, the key after the
            <code class="font-mono text-text">#</code>, a query string, anything under
            <code class="font-mono text-text">/api</code>, a file the page loads, and the health
            and metrics routes. Opening a secret is not recorded as an event.
          </li>
          <li>
            Not counted at all: a visitor who sends Do Not Track or Global Privacy Control, a
            prefetch, a bot, and a client on a private address.
          </li>
          <li>
            The server still never receives a key or a plaintext. Counting changes none of that:
            the key stays in the part of the link after the
            <code class="font-mono text-text">#</code>, which a browser does not send.
          </li>
        </ul>
        <p class="text-sm">
          The legal privacy notice of the operator is a separate text and is not written here.
        </p>
      </div>
    </GovueCard>

    <GovueCard as="section" title="Where this stops helping">
      <ul class="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
        <li>
          Anyone who gets the link gets the secret. Encryption in the browser does not make a
          careless channel safe.
        </li>
        <li>
          This server cannot read a stored secret, but it serves the code that does the encrypting.
          A server that has been taken over could serve different code. End to end encryption in a
          browser is worth exactly as much as the delivery of the page.
        </li>
        <li>
          Both ends are outside it. The secret came from somewhere before the form, and after the
          reveal it sits in a window on someone else's screen.
        </li>
        <li>
          That a secret was created and opened is visible to the server. Only the content is not.
        </li>
      </ul>

      <template #footer>
        <a
          href="/"
          class="inline-flex min-h-11 items-center text-base text-accent-text transition-colors hover:underline"
        >
          Back to the start
        </a>
      </template>
    </GovueCard>
  </GovuePage>
</template>
