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
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { clearToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { EXPIRING_TOKEN_ID } from '@openidentityplatform/commons-ui-next/mock'
import SessionGuard from './SessionGuard.tsx'

// isSelfServiceUser always returns false today (no role field on AmSessionInfo yet — real
// wiring is P2-4). Mocking it here verifies SessionGuard's routing branch is wired correctly
// ahead of that, isolated in its own file since vi.mock is hoisted for the whole test file.
vi.mock('./isSelfServiceUser.ts', () => ({ isSelfServiceUser: () => true }))

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

describe('SessionGuard — self-service role (mocked)', () => {
  afterEach(() => {
    clearToken()
  })

  it('navigates to /sessionExpired instead of opening the dialog', async () => {
    setToken(EXPIRING_TOKEN_ID)
    renderGuard()

    expect(await screen.findByText('Session expired view')).toBeInTheDocument()
    expect(screen.queryByText('Session Expired')).toBeNull()
  })
})
