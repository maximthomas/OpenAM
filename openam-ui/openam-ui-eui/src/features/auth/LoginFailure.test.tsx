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
import { MemoryRouter } from 'react-router'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import { getToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import LoginFailure from './LoginFailure.tsx'

function renderLoginFailure() {
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <MemoryRouter>
        <LoginFailure />
      </MemoryRouter>
    </I18nextProvider>,
  )
}

describe('LoginFailure', () => {
  it('shows the unavailable title and clears the token', async () => {
    setToken('leftover-token')

    renderLoginFailure()

    expect(await screen.findByText('Unable to login to OpenAM')).toBeInTheDocument()
    expect(getToken()).toBeNull()
  })

  it('renders a return-to-login link', async () => {
    renderLoginFailure()

    const link = await screen.findByRole('link', { name: 'Return to Login Page' })
    expect(link.getAttribute('href')).toContain('/login')
  })
})
