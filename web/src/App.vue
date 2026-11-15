<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { computed } from 'vue'
import { GovuePage } from '@ostendorf-cloud/govue'

import CreateRequestLink from './views/CreateRequestLink.vue'
import RequestLinkView from './views/RequestLinkView.vue'

// There is no router dependency here: a request link's own page is told
// apart from the home page by the URL path alone, /r/<id>, which is all
// this app has needed a second route for so far. See AGENTS.md's "web/"
// entry for why nothing heavier was reached for.
const requestLinkID = computed(() => {
  const match = /^\/r\/([^/]+)$/.exec(window.location.pathname)
  return match ? decodeURIComponent(match[1]) : null
})
</script>

<template>
  <RequestLinkView v-if="requestLinkID" :id="requestLinkID" />
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
</template>
