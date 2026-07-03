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
  AUTH_CHALLENGE,
  AUTH_CHALLENGE_REDIRECT_POST,
  AUTH_TIMEOUT_ERROR,
  existingSessionAuthenticateHandler,
  existingSessionOtherRealmHandler,
  make408ThenRecoverHandler,
  makeZeroPageRejectHandler,
  MOCK_GOTO_ALLOWED,
  MOCK_GOTO_REJECTED,
  multiStageAuthenticateHandler,
  pollingAuthenticateHandler,
  redirectAuthenticateHandler,
  REDIRECT_POST_AUTH_ID,
  SERVER_INFO,
  SERVER_INFO_ZERO_PAGE_ENABLED,
} from '@openidentityplatform/commons-ui-next/mock'
import { getToken, setToken } from '@openidentityplatform/commons-ui-next/session'
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

describe('LoginPage — return-leg resume (P1-5i)', () => {
  afterEach(() => {
    // jsdom does not reset document.cookie between tests — clear it explicitly.
    document.cookie = 'authId=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
  })

  it('sets the tracking cookie before navigating away when a redirect carries a trackingCookie', async () => {
    const submitSpy = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {})

    server.use(
      http.post('*/json/authenticate', () => HttpResponse.json(AUTH_CHALLENGE_REDIRECT_POST)),
      http.post('*/json/realms/root/authenticate', () => HttpResponse.json(AUTH_CHALLENGE_REDIRECT_POST)),
    )

    renderApp('/login')

    await waitFor(() => {
      expect(document.cookie).toContain(`authId=${REDIRECT_POST_AUTH_ID}`)
    })

    submitSpy.mockRestore()
  })

  it('resumes (no begin) when a tracking cookie is present on mount, and clears it on success', async () => {
    document.cookie = `authId=${REDIRECT_POST_AUTH_ID};path=/`
    let sawInitialBeginCall = false

    const resumeOrFail = async (request: Request): Promise<Response> => {
      const body = (await request.json()) as { authId?: string }
      if (!body.authId) {
        sawInitialBeginCall = true
        return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'unexpected begin() call' })
      }
      if (body.authId === REDIRECT_POST_AUTH_ID) {
        return HttpResponse.json({ tokenId: 'resumed-token-id', successUrl: '/openam/console', realm: '/' })
      }
      return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'unexpected authId' })
    }

    server.use(
      http.post('*/json/authenticate', ({ request }) => resumeOrFail(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => resumeOrFail(request)),
    )

    renderApp('/login')

    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
    expect(sawInitialBeginCall).toBe(false)
    expect(document.cookie).not.toContain('authId=')
  })

  it('shows the timeout message without restarting when a tracked authId 408s', async () => {
    document.cookie = `authId=${REDIRECT_POST_AUTH_ID};path=/`

    server.use(
      http.post('*/json/authenticate', () => HttpResponse.json(AUTH_TIMEOUT_ERROR, { status: 408 })),
      http.post('*/json/realms/root/authenticate', () => HttpResponse.json(AUTH_TIMEOUT_ERROR, { status: 408 })),
    )

    renderApp('/login')

    expect(await screen.findByText('Login processed timed out. Restarting...')).toBeInTheDocument()
    // No restart: the login form never appears, and the cookie is not cleared (legacy only
    // clears the token on a resolved response, not on a 401/408 failure).
    expect(screen.queryByLabelText('User Name')).toBeNull()
    expect(document.cookie).toContain(`authId=${REDIRECT_POST_AUTH_ID}`)
  })
})

describe('LoginPage — goto param + validateGoto (P1-5d)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('navigates to the validated goto URL after successful login', async () => {
    // Stub window.location so jsdom does not throw on external href assignment.
    vi.stubGlobal('location', { href: 'http://localhost/', replace: vi.fn() })

    const user = userEvent.setup()
    renderApp(`/login?goto=${encodeURIComponent(MOCK_GOTO_ALLOWED)}`)

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() => {
      expect(window.location.href).toBe(MOCK_GOTO_ALLOWED)
    })
  })

  it('falls back to app home when goto is rejected by AM', async () => {
    const user = userEvent.setup()
    renderApp(`/login?goto=${encodeURIComponent(MOCK_GOTO_REJECTED)}`)

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    // goto rejected → fall back to EUI home page.
    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
  })

  it('threads authIndexType/authIndexValue into the /authenticate request URL', async () => {
    let capturedUrl: string | null = null

    server.use(
      http.post('*/json/authenticate', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'fail' }, { status: 401 })
      }),
      http.post('*/json/realms/root/authenticate', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'fail' }, { status: 401 })
      }),
    )

    renderApp('/login?module=DataStore')

    await waitFor(() => {
      expect(capturedUrl).not.toBeNull()
    })

    const url = new URL(capturedUrl!)
    expect(url.searchParams.get('authIndexType')).toBe('module')
    expect(url.searchParams.get('authIndexValue')).toBe('DataStore')
  })
})

describe('LoginPage — existing session (P1-5e)', () => {
  it('redirects to home when existing session realm matches URL realm', async () => {
    server.use(
      http.post('*/json/authenticate', () => existingSessionAuthenticateHandler()),
      http.post('*/json/realms/root/authenticate', () => existingSessionAuthenticateHandler()),
    )

    renderApp('/login')

    // Existing session in same realm ('/') → navigate to home directly.
    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
  })

  it('redirects to /confirmLogin when session realm differs from URL realm', async () => {
    server.use(
      http.post('*/json/authenticate', () => existingSessionOtherRealmHandler()),
      http.post('*/json/realms/root/authenticate', () => existingSessionOtherRealmHandler()),
    )

    renderApp('/login')

    // Realm changed: AUTH_SUCCESS_OTHER_REALM has realm '/other-realm', URL has realm '/'.
    expect(await screen.findByText(/logged you out of the previous site/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /log in to new site/i })).toBeInTheDocument()
  })
})

describe('LoginPage — arg=newsession (P1-5e)', () => {
  it('clears the stored token on mount when arg=newsession', async () => {
    const { getToken, setToken: storeToken } = await import('@openidentityplatform/commons-ui-next/session')
    // Pre-store a token to simulate a leftover session.
    storeToken('existing-token-to-clear')
    expect(getToken()).toBe('existing-token-to-clear')

    renderApp('/login?arg=newsession')

    // After mount, LoginPage should have called clearToken().
    await waitFor(() => {
      expect(getToken()).toBeNull()
    })
  })
})

describe('LoginPage — zero-page auto-login (P1-5e, referrer gate P1-5h)', () => {
  it('auto-submits IDToken params and succeeds when zeroPageLogin.enabled is true', async () => {
    // Enable zero-page in the server info mock. The default authenticate handler handles
    // IDToken1=demo&IDToken2=changeit → AUTH_CHALLENGE (initial) → AUTH_SUCCESS (submit).
    server.use(http.get('*/json/serverinfo/:attribute', () => HttpResponse.json(SERVER_INFO_ZERO_PAGE_ENABLED)))

    renderApp('/login?IDToken1=demo&IDToken2=changeit')

    // Zero-page auto-submit fills callbacks and submits → home page.
    expect(await screen.findByRole('heading', { name: /openam eui/i }, { timeout: 3000 })).toBeInTheDocument()
  })

  it('shows the form normally when zeroPageLogin.enabled is false', async () => {
    // Server info has zeroPageLogin.enabled: false (default mock fixture).
    renderApp('/login?IDToken1=demo&IDToken2=changeit')

    // Form should render — no auto-submit.
    expect(await screen.findByRole('button', { name: 'Submit' })).toBeInTheDocument()
  })

  it('does not retry auto-submit when AM rejects the zero-page credentials', async () => {
    // Reject only the submit (authId present); restarts (no authId) get AUTH_CHALLENGE so
    // the form can render and the test can confirm no second auto-submit occurs.
    const handler = makeZeroPageRejectHandler()
    server.use(
      http.get('*/json/serverinfo/:attribute', () => HttpResponse.json(SERVER_INFO_ZERO_PAGE_ENABLED)),
      http.post('*/json/authenticate', ({ request }) => handler(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => handler(request)),
    )

    renderApp('/login?IDToken1=wrong&IDToken2=bad')

    // After the failed auto-submit the flow restarts and the form should reappear.
    expect(await screen.findByRole('button', { name: 'Submit' }, { timeout: 3000 })).toBeInTheDocument()
  })

  it('shows the form with no auto-submit when the referrer is not on the whitelist', async () => {
    // enabled + allowedWithoutReferer: false + a whitelist that doesn't include the stubbed referrer.
    Object.defineProperty(document, 'referrer', { value: 'https://untrusted.example.com', configurable: true })
    server.use(
      http.get('*/json/serverinfo/:attribute', () =>
        HttpResponse.json({
          ...SERVER_INFO,
          zeroPageLogin: {
            enabled: true,
            refererWhitelist: ['https://trusted.example.com'],
            allowedWithoutReferer: false,
          },
        }),
      ),
    )

    renderApp('/login?IDToken1=demo&IDToken2=changeit')

    // Referrer gate rejects the auto-submit — the form renders normally instead.
    expect(await screen.findByRole('button', { name: 'Submit' })).toBeInTheDocument()

    Object.defineProperty(document, 'referrer', { value: '', configurable: true })
  })
})

describe('LoginPage — failure navigation (P1-5f)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('navigates to the validated gotoOnFail URL after a login failure', async () => {
    vi.stubGlobal('location', { href: 'http://localhost/', replace: vi.fn() })

    const user = userEvent.setup()
    renderApp(`/login?gotoOnFail=${encodeURIComponent(MOCK_GOTO_ALLOWED)}`)

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() => {
      expect(window.location.href).toBe(MOCK_GOTO_ALLOWED)
    })
  })

  it('falls back to the failure message and restarts when gotoOnFail is rejected by AM', async () => {
    const user = userEvent.setup()
    renderApp(`/login?gotoOnFail=${encodeURIComponent(MOCK_GOTO_REJECTED)}`)

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByText('User name/password combination is invalid.')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Submit' })).toBeEnabled()
  })

  it('hard-navigates to detail.failureUrl on a failure response, bypassing validateGoto', async () => {
    vi.stubGlobal('location', { href: 'http://localhost/', replace: vi.fn() })

    const failOnSubmit = async (request: Request): Promise<Response> => {
      const text = await request.text()
      const body = (text ? JSON.parse(text) : {}) as { authId?: string }
      if (!body.authId) return HttpResponse.json(AUTH_CHALLENGE)
      return HttpResponse.json(
        { code: 401, reason: 'Unauthorized', message: 'fail', detail: { failureUrl: 'http://failure.example.com/retry' } },
        { status: 401 },
      )
    }
    server.use(
      http.post('*/json/authenticate', ({ request }) => failOnSubmit(request)),
      http.post('*/json/realms/root/authenticate', ({ request }) => failOnSubmit(request)),
    )

    const user = userEvent.setup()
    renderApp('/login')

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() => {
      expect(window.location.href).toBe('http://failure.example.com/retry')
    })
  })
})

describe('LoginPage — start failure (P1-5f)', () => {
  it('navigates to /failedLogin and clears the token when startAuthentication throws', async () => {
    setToken('leftover-token')
    server.use(
      http.post('*/json/authenticate', () => HttpResponse.error()),
      http.post('*/json/realms/root/authenticate', () => HttpResponse.error()),
    )

    renderApp('/login')

    expect(await screen.findByText('Unable to login to OpenAM')).toBeInTheDocument()
    expect(getToken()).toBeNull()
  })
})

describe('LoginPage — remember-me (P1-5j)', () => {
  afterEach(() => {
    // jsdom does not reset document.cookie between tests — clear it explicitly.
    document.cookie = 'login=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
  })

  it('remembers the username when the checkbox is checked on submit', async () => {
    const user = userEvent.setup()
    renderApp('/login')

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('checkbox', { name: 'Remember my username' }))
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
    expect(document.cookie).toContain('login=demo')
  })

  it('clears the remembered username when the checkbox is left unchecked on submit', async () => {
    const user = userEvent.setup()
    renderApp('/login')

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
    expect(document.cookie).not.toContain('login=demo')
  })

  it('pre-fills the username, checks the box, and focuses the password field on a later visit', async () => {
    document.cookie = 'login=demo;path=/'

    renderApp('/login')

    const usernameField = await screen.findByLabelText('User Name')
    expect(usernameField).toHaveValue('demo')
    expect(screen.getByRole('checkbox', { name: 'Remember my username' })).toBeChecked()
    expect(screen.getByLabelText('Password')).toHaveFocus()
  })

  it('clears the remembered username when unchecked and submitted on a later visit', async () => {
    document.cookie = 'login=demo;path=/'
    const user = userEvent.setup()
    renderApp('/login')

    await screen.findByLabelText('User Name')
    await user.click(screen.getByRole('checkbox', { name: 'Remember my username' }))
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByRole('heading', { name: /openam eui/i })).toBeInTheDocument()
    expect(document.cookie).not.toContain('login=demo')
  })
})
