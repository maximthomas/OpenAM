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

import type { ReactNode } from 'react'
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import { AppShell, Footer, Nav } from '@openidentityplatform/commons-ui-next/shell'
import { createI18nInstance, I18nextProvider } from '@openidentityplatform/commons-ui-next/i18n'
import {
  CrossLinkProvider,
  createCrossLinkResolver,
} from '@openidentityplatform/commons-ui-next/routing'

// Resolver used by the nav CrossLinks: `login` still lives in the legacy /XUI app, `dashboard` is
// owned by this (eui) app — mirrors the coexistence handoff behaviour under test.
const resolver = createCrossLinkResolver({
  routes: [
    { path: 'login', owner: 'xui' },
    { path: 'dashboard', owner: 'eui' },
  ],
  mounts: { eui: '/EUI', xui: '/XUI' },
  currentOwner: 'eui',
})

// AppShell is a layout route: render it with a child route so <Outlet> resolves.
function renderShell(shell: ReactNode) {
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <CrossLinkProvider resolver={resolver}>
        <MemoryRouter initialEntries={['/']}>
          <Routes>
            <Route element={shell}>
              <Route path="/" element={<p>outlet content</p>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </CrossLinkProvider>
    </I18nextProvider>,
  )
}

const dashboardNav = <Nav items={[{ id: 'dash', label: 'Dashboard', to: 'dashboard' }]} ariaLabel="Main" />

describe('AppShell', () => {
  it('renders brand, routed outlet content and the footer copyright', () => {
    renderShell(<AppShell brand={<span>Brand Co</span>} />)

    expect(screen.getByText('Brand Co')).toBeInTheDocument()
    expect(screen.getByText('outlet content')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'OpenAM' })).toHaveAttribute(
      'href',
      'https://github.com/OpenIdentityPlatform/OpenAM/blob/master/README.md',
    )
  })

  it('shows the nav in the default (app) variant', () => {
    renderShell(<AppShell brand={<span>Brand Co</span>} nav={dashboardNav} />)
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument()
  })

  it('hides the nav in the minimal (auth) variant', () => {
    renderShell(<AppShell variant="auth" brand={<span>Brand Co</span>} nav={dashboardNav} />)
    expect(screen.queryByRole('link', { name: 'Dashboard' })).toBeNull()
  })
})

describe('Footer', () => {
  const withI18n = (ui: ReactNode) => <I18nextProvider i18n={createI18nInstance()}>{ui}</I18nextProvider>

  it('omits the build line when no version is given', () => {
    render(withI18n(<Footer />))
    expect(screen.queryByText(/build/i)).toBeNull()
  })

  it('renders the build line when a version is given', () => {
    render(withI18n(<Footer version="7.0.0" />))
    expect(screen.getByText('Build 7.0.0')).toBeInTheDocument()
  })
})

describe('Nav', () => {
  it('renders a cross-app item as a full-page handoff and a same-app item as an in-app link', () => {
    render(
      <CrossLinkProvider resolver={resolver}>
        <MemoryRouter>
          <Nav
            items={[
              { id: 'login', label: 'Sign in', to: 'login' },
              { id: 'dash', label: 'Dashboard', to: 'dashboard' },
            ]}
            ariaLabel="Main"
          />
        </MemoryRouter>
      </CrossLinkProvider>,
    )

    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/XUI/login')
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/dashboard')
  })
})
