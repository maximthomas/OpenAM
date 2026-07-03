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
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { clearToken, getToken } from '@openidentityplatform/commons-ui-next/session'
import { DEMO_TOKEN_ID } from '@openidentityplatform/commons-ui-next/mock'
import SessionTimeoutDialog from './SessionTimeoutDialog.tsx'

function renderDialog(onResume: () => void = () => {}) {
  const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <QueryClientProvider client={queryClient}>
        <SessionTimeoutDialog onResume={onResume} />
      </QueryClientProvider>
    </I18nextProvider>,
  )
}

describe('SessionTimeoutDialog', () => {
  afterEach(() => {
    clearToken()
  })

  it('re-authenticates with demo/changeit and calls onResume with a fresh token, without navigating', async () => {
    const user = userEvent.setup()
    let resumed = false
    renderDialog(() => {
      resumed = true
    })

    expect(await screen.findByText('Session Expired')).toBeInTheDocument()

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'changeit')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    await waitFor(() => expect(resumed).toBe(true))
    expect(getToken()).toBe(DEMO_TOKEN_ID)
  })

  it('shows an error and lets the user retry on invalid credentials', async () => {
    const user = userEvent.setup()
    renderDialog()

    await user.type(await screen.findByLabelText('User Name'), 'demo')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Submit' }))

    expect(await screen.findByText('User name/password combination is invalid.')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Submit' })).toBeEnabled()
  })
})
