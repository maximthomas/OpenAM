/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems LLC.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http } from 'msw'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { multiStageAuthenticateHandler } from '@openidentityplatform/commons-ui-next/mock'
import { server } from '../../test/setup.ts'
import App from '../../App.tsx'

function renderApp(initialPath: string) {
  const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[initialPath]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>
    </I18nextProvider>,
  )
}

describe('LoginPage', () => {
  it('logs in with valid credentials and redirects to Home', async () => {
    const user = userEvent.setup()
    renderApp('/login')

    // Labels come from the AM challenge prompt output (colon trimmed): 'User Name:' → 'User Name'
    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
  })

  it('shows an error and re-enables submit on invalid credentials', async () => {
    const user = userEvent.setup()
    renderApp('/login')

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByText('User name/password combination is invalid.')).toBeInTheDocument()
    // After failure the hook auto-restarts; wait for the form to reappear.
    expect(await screen.findByRole('button', { name: 'Submit' })).toBeEnabled()
  })

  it('walks through a two-stage login (username stage → password stage)', async () => {
    // Override the initial authenticate response to return the username-only stage.
    server.use(http.post('*/json/authenticate', ({ request }) => multiStageAuthenticateHandler(request)))
    server.use(
      http.post('*/json/realms/root/authenticate', ({ request }) => multiStageAuthenticateHandler(request)),
    )

    const user = userEvent.setup()
    renderApp('/login')

    // Stage 1: only username field visible
    const usernameField = await screen.findByLabelText('User Name')
    expect(screen.queryByLabelText('Password')).toBeNull()
    await user.type(usernameField, 'demo')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    // Stage 2: only password field visible
    const passwordField = await screen.findByLabelText('Password')
    expect(screen.queryByLabelText('User Name')).toBeNull()
    await user.type(passwordField, 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    // Success → redirected to home
    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
  })
})
