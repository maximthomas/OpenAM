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

import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import {
  AUTH_CHALLENGE_REDIRECT_POST,
  make408ThenRecoverHandler,
  multiStageAuthenticateHandler,
  pollingAuthenticateHandler,
  redirectAuthenticateHandler,
} from '@openidentityplatform/commons-ui-next/mock'
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

// Helpers for redirect tests — vi.stubGlobal replaces window.location without hitting
// jsdom's non-configurable location.replace descriptor.
describe('LoginPage — RedirectCallback (P1-5c)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('calls window.location.replace for a GET redirect challenge', async () => {
    const replaceFn = vi.fn()
    // Stub the whole location object; provide a valid href so MSW can resolve relative fetch URLs.
    vi.stubGlobal('location', { replace: replaceFn, href: 'http://localhost/' })

    server.use(
      http.post('*/json/authenticate', ({ request }) => redirectAuthenticateHandler(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => redirectAuthenticateHandler(request)),
    )

    renderApp('/login')

    await waitFor(() => {
      expect(replaceFn).toHaveBeenCalledWith('https://mock-idp.example.com/oauth2/authorize')
    })
  })

  it('shows a spinner while the GET redirect is in progress', async () => {
    vi.stubGlobal('location', { replace: vi.fn(), href: 'http://localhost/' })

    server.use(
      http.post('*/json/authenticate', ({ request }) => redirectAuthenticateHandler(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => redirectAuthenticateHandler(request)),
    )

    renderApp('/login')

    expect(await screen.findByRole('status')).toBeInTheDocument()
  })

  it('submits a hidden POST form for a POST redirect challenge', async () => {
    const submitSpy = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {})

    server.use(
      http.post('*/json/authenticate', () => HttpResponse.json(AUTH_CHALLENGE_REDIRECT_POST)),
      http.post('*/json/realms/root/authenticate', () => HttpResponse.json(AUTH_CHALLENGE_REDIRECT_POST)),
    )

    renderApp('/login')

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledOnce()
    })
    submitSpy.mockRestore()
  })
})

describe('LoginPage — PollingWaitCallback (P1-5c)', () => {
  it('auto-submits polling stages and succeeds', async () => {
    server.use(
      http.post('*/json/authenticate', ({ request }) => pollingAuthenticateHandler(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => pollingAuthenticateHandler(request)),
    )

    renderApp('/login')

    // Fixtures use 50ms wait time — two polls then success → home page.
    expect(await screen.findByRole('heading', { name: /openam eui/i }, { timeout: 3000 })).toBeInTheDocument()
  })
})

describe('LoginPage — 408 timeout restart (P1-5c)', () => {
  it('restarts the authentication flow after a 408 timeout', async () => {
    const handler = make408ThenRecoverHandler()
    server.use(
      http.post('*/json/authenticate', ({ request }) => handler(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => handler(request)),
    )

    renderApp('/login')

    // After the 408, the hook restarts — the login form should reappear.
    expect(await screen.findByLabelText('User Name', {}, { timeout: 3000 })).toBeInTheDocument()
  })
})
