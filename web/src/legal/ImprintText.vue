<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { useLanguage } from '@ostendorf-cloud/govue'

// The imprint text of burnlink. It names the operator and nothing else, the
// same facts in German and English. The English page says that the German
// text is the binding one.
const { locale } = useLanguage()
</script>

<template>
  <div v-if="locale === 'de'" class="flex flex-col gap-4 text-text" data-testid="imprint-de">
    <h2 class="text-xl font-semibold text-text">Anbieter</h2>
    <p>
      Simon Ostendorf<br />
      Frankenstr. 8<br />
      52070 Aachen<br />
      Deutschland
    </p>

    <h2 class="text-xl font-semibold text-text">Kontakt</h2>
    <p>
      Telefon:
      <a class="text-accent-text hover:underline" href="tel:+4915730971784">+49 1573 0971784</a
      ><br />
      E-Mail:
      <a class="text-accent-text hover:underline" href="mailto:info@burnlink.de"
        >info@burnlink.de</a
      >
    </p>

    <h2 class="text-xl font-semibold text-text">Umsatzsteuer-ID</h2>
    <p>Umsatzsteuer-Identifikationsnummer gemäß §27a Umsatzsteuergesetz: DE362164357</p>
  </div>

  <div v-else class="flex flex-col gap-4 text-text" data-testid="imprint-en">
    <p class="text-text-muted">
      The German text is the legally binding one.
      <a class="text-accent-text hover:underline" href="/de/imprint">Read the German version</a>
    </p>

    <h2 class="text-xl font-semibold text-text">Provider</h2>
    <p>
      Simon Ostendorf<br />
      Frankenstr. 8<br />
      52070 Aachen<br />
      Germany
    </p>

    <h2 class="text-xl font-semibold text-text">Contact</h2>
    <p>
      Phone:
      <a class="text-accent-text hover:underline" href="tel:+4915730971784">+49 1573 0971784</a
      ><br />
      Email:
      <a class="text-accent-text hover:underline" href="mailto:info@burnlink.de"
        >info@burnlink.de</a
      >
    </p>

    <h2 class="text-xl font-semibold text-text">VAT ID</h2>
    <p>VAT identification number per Section 27a of the German VAT Act: DE362164357</p>
  </div>
</template>
