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

import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { clearToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { EXPIRING_TOKEN_ID } from '@openidentityplatform/commons-ui-next/mock'
import SessionGuard from './SessionGuard.tsx'

const POLL_MS = 20

function renderGuard() {
  const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/']}>
          <Routes>
            <Route element={<SessionGuard pollIntervalMs={POLL_MS} />}>
              <Route path="/" element={<div>Home content</div>} />
            </Route>
            <Route path="/sessionExpired" element={<div>Session expired view</div>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </I18nextProvider>,
  )
}

// Default role branch (isSelfServiceUser() is false until real role wiring lands in P2-4) — see
// SessionGuard.selfService.test.tsx for the mocked self-service navigation branch.
describe('SessionGuard', () => {
  afterEach(() => {
    clearToken()
  })

  it('opens the re-auth dialog on expiry and resumes in place (no navigation) once re-authenticated', async () => {
    setToken(EXPIRING_TOKEN_ID)
    const user = userEvent.setup()
    renderGuard()

    expect(screen.getByText('Home content')).toBeInTheDocument()
    expect(await screen.findByText('Session Expired')).toBeInTheDocument()

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() => expect(screen.queryByText('Session Expired')).toBeNull())
    expect(screen.getByText('Home content')).toBeInTheDocument()
  })
})
