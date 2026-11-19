<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { computed } from 'vue'
import {
  GovueFooter,
  GovueHeader,
  GovueNav,
  GovuePage,
  GovueSkipLink,
} from '@ostendorf-cloud/govue'

import CreateRequestLink from './views/CreateRequestLink.vue'
import RequestLinkView from './views/RequestLinkView.vue'
import RevealSecretView from './views/RevealSecretView.vue'
import SecurityView from './views/SecurityView.vue'
import ShareSecret from './views/ShareSecret.vue'

// There is no router dependency here: a request link's own page is told
// apart from the home page by the URL path alone, /r/<id>, and the security
// page is /security. See AGENTS.md's "web/" entry for why nothing heavier
// was reached for.
const requestLinkID = computed(() => {
  const match = /^\/r\/([^/]+)$/.exec(window.location.pathname)
  return match ? decodeURIComponent(match[1]) : null
})
const secretID = computed(() => {
  const match = /^\/s\/([^/]+)$/.exec(window.location.pathname)
  return match ? decodeURIComponent(match[1]) : null
})
const onSecurityPage = window.location.pathname === '/security'

// The header names no wordmark on purpose: the project has no visual
// identity yet, see AGENTS.md's deviations.
const navItems = [
  { href: '/', label: 'Home', current: window.location.pathname === '/' },
  { href: '/security', label: 'How the encryption works', current: onSecurityPage },
]
const footerLinks = [{ href: '/security', label: 'How the encryption works' }]
</script>

<template>
  <GovueSkipLink />
  <GovueHeader>
    <template #brand>
      <a href="/" class="text-text">burnlink</a>
    </template>
    <GovueNav :items="navItems" />
  </GovueHeader>

  <SecurityView v-if="onSecurityPage" />
  <RequestLinkView v-else-if="requestLinkID" :id="requestLinkID" />
  <RevealSecretView v-else-if="secretID" :id="secretID" />
  <GovuePage
    v-else
    title="burnlink"
    lead="One time secret sharing: the browser encrypts, the server hands it out exactly once."
  >
    <ShareSecret />
    <CreateRequestLink />
  </GovuePage>

  <GovueFooter :legal="['imprint', 'privacy']" :links="footerLinks" />
</template>
