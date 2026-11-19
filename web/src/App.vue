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
import SecurityView from './views/SecurityView.vue'

// There is no router dependency here: a request link's own page is told
// apart from the home page by the URL path alone, /r/<id>, and the security
// page is /security. See AGENTS.md's "web/" entry for why nothing heavier
// was reached for.
const requestLinkID = computed(() => {
  const match = /^\/r\/([^/]+)$/.exec(window.location.pathname)
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
  <GovuePage
    v-else
    title="burnlink"
    lead="One time secret sharing: the browser encrypts, the server hands it out exactly once."
  >
    <p class="text-text-muted">
      Sending a one-time secret through a link is not built into this page yet.
    </p>
    <CreateRequestLink />
  </GovuePage>

  <GovueFooter :legal="['imprint', 'privacy']" :links="footerLinks" />
</template>
