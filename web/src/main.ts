// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { createApp, h } from 'vue'
import { createGovueI18n, localeFromPath, useTheme } from '@ostendorf-cloud/govue'

import App from './App.vue'
import LegalView from './legal/LegalView.vue'
import { legalPageForPath } from './legal/pages'
import './styles.css'

// The theme never varies: this app ships exactly one brand. Mode starts at
// "system", the visitor's own choice only overrides it once they use a
// toggle, matching useTheme's own documented default. There is no router
// yet: the app pages are told apart by the URL path alone.
useTheme({ theme: 'burnlink' })

// A legal page is prerendered per language, /de/imprint and the others. The
// client replaces that markup with createApp, never hydrates it, and takes
// the language from the path. The app pages stay English and have no
// language layer.
const legalPage = legalPageForPath(window.location.pathname)
if (legalPage) {
  const app = createApp({ render: () => h(LegalView, { page: legalPage }) })
  app.use(createGovueI18n({ locale: localeFromPath(window.location.pathname) }))
  app.mount('#app')
} else {
  createApp(App).mount('#app')
}
