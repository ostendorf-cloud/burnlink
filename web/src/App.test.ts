// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/vue'
import { describe, expect, it } from 'vitest'

import App from './App.vue'

describe('App', () => {
  it('renders the repository name as the page heading', () => {
    render(App)

    expect(screen.getByRole('heading', { name: 'burnlink' })).toBeVisible()
  })

  it('renders the one-line description as the placeholder lead', () => {
    render(App)

    expect(
      screen.getByText(
        'One time secret sharing: the browser encrypts, the server hands it out exactly once.',
      ),
    ).toBeVisible()
  })
})
