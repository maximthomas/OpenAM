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
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { getToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { DEMO_TOKEN_ID } from '@openidentityplatform/commons-ui-next/mock'
import { server } from '../../test/setup.ts'
import Logout from './Logout.tsx'

function renderLogout() {
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <MemoryRouter>
        <Logout />
      </MemoryRouter>
    </I18nextProvider>,
  )
}

describe('Logout', () => {
  it('calls _action=logout when a token is present, then clears it', async () => {
    setToken(DEMO_TOKEN_ID)
    let calledAction: string | null = null
    const recordAction = ({ request }: { request: Request }) => {
      calledAction = new URL(request.url).searchParams.get('_action')
      return HttpResponse.json({ result: true })
    }
    server.use(
      http.post('*/json/sessions', recordAction),
      http.post('*/json/realms/root/sessions', recordAction),
    )

    renderLogout()

    expect(await screen.findByText('You have been logged out.')).toBeInTheDocument()
    await waitFor(() => expect(calledAction).toBe('logout'))
    expect(getToken()).toBeNull()
  })

  it('clears the token even when no session existed (best-effort logout)', async () => {
    renderLogout()

    expect(await screen.findByText('You have been logged out.')).toBeInTheDocument()
    expect(getToken()).toBeNull()
  })
})
