<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { GovueFooter, GovueLegalPage, type LegalPage } from '@ostendorf-cloud/govue'

import ImprintText from './ImprintText.vue'
import PrivacyText from './PrivacyText.vue'

// One legal page: govue's shell around the site's own text, and the footer
// that links the legal pages, which govue-check-legal requires on every
// prerendered page. burnlink has no terms, so there is no terms page.
defineProps<{ page: Exclude<LegalPage, 'terms'> }>()
</script>

<template>
  <!-- The start page is not language prefixed, so the back link goes to /. -->
  <GovueLegalPage :page="page" back-href="/">
    <ImprintText v-if="page === 'imprint'" />
    <PrivacyText v-else />
  </GovueLegalPage>
  <GovueFooter :legal="['imprint', 'privacy']" />
</template>
