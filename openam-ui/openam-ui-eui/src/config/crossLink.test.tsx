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
import { MemoryRouter } from 'react-router'
import {
  CrossLink,
  CrossLinkProvider,
  createCrossLinkResolver,
} from '@openidentityplatform/commons-ui-next/routing'

function renderWithResolver(ui: ReactNode) {
  const resolver = createCrossLinkResolver({
    routes: [
      { path: 'login', owner: 'xui' },
      { path: 'dashboard', owner: 'eui' },
    ],
    mounts: { eui: '/EUI', xui: '/XUI' },
    currentOwner: 'eui',
  })
  return render(
    <MemoryRouter>
      <CrossLinkProvider resolver={resolver}>{ui}</CrossLinkProvider>
    </MemoryRouter>,
  )
}

describe('CrossLink', () => {
  it('renders a full-page <a> to the legacy mount for a cross-boundary route', () => {
    renderWithResolver(<CrossLink to="login">Sign in</CrossLink>)
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/XUI/login')
  })

  it('renders an in-app router link for a same-app route', () => {
    renderWithResolver(<CrossLink to="dashboard">Dashboard</CrossLink>)
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/dashboard')
  })

  it('same-app link renders the resolver href, not a mount-prefixed cross-boundary URL', () => {
    renderWithResolver(<CrossLink to="dashboard">Dashboard</CrossLink>)
    const link = screen.getByRole('link', { name: 'Dashboard' })
    expect(link).toHaveAttribute('href', '/dashboard')
    expect(link).not.toHaveAttribute('href', expect.stringContaining('/EUI/'))
    expect(link).not.toHaveAttribute('href', expect.stringContaining('/XUI/'))
  })

  it('forwards anchor props (e.g. className) to the rendered link', () => {
    renderWithResolver(<CrossLink to="login" className="nav-link">Sign in</CrossLink>)
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveClass('nav-link')
  })
})
