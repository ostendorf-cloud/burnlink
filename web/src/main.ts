// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { createApp } from 'vue'
import { useTheme } from '@ostendorf-cloud/govue'

import App from './App.vue'
import './styles.css'

// The theme never varies: this app ships exactly one brand. Mode starts at
// "system", the visitor's own choice only overrides it once they use a
// toggle, matching useTheme's own documented default. There is no router
// yet: this scaffold renders one placeholder page.
useTheme({ theme: 'burnlink' })

const app = createApp(App)
app.mount('#app')
