<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { computed } from 'vue'
import {
  GovueErrorState,
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
// An id that is not valid percent encoding, such as /s/%C3%28, is no page of
// the site: the match fails and the home page's not found state shows.
function idFromPath(prefix: string): string | null {
  const match = new RegExp(`^/${prefix}/([^/]+)$`).exec(window.location.pathname)
  if (!match) return null
  try {
    return decodeURIComponent(match[1])
  } catch {
    return null
  }
}
const requestLinkID = computed(() => idFromPath('r'))
const secretID = computed(() => idFromPath('s'))
const notFound = computed(
  () => /^\/[rs]\/[^/]+$/.test(window.location.pathname) && !requestLinkID.value && !secretID.value,
)
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
  <GovueHeader theme-switch>
    <template #brand>
      <a href="/" class="text-text">burnlink</a>
    </template>
    <GovueNav :items="navItems" />
  </GovueHeader>

  <SecurityView v-if="onSecurityPage" />
  <GovuePage v-else-if="notFound">
    <GovueErrorState
      title="This page does not exist"
      message="The address is not valid. Check that the link was copied completely."
    />
  </GovuePage>
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
