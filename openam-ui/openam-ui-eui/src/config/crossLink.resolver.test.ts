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
import {
  createCrossLinkResolver,
  type CrossLinkConfig,
} from '@openidentityplatform/commons-ui-next/routing'

const config: CrossLinkConfig = {
  routes: [
    { path: 'login', owner: 'xui' },
    { path: 'dashboard', owner: 'eui' },
    { path: 'realms', owner: 'xui' },
    { path: 'realms/*/authentication', owner: 'xui' },
    { path: 'realms/*/sessions', owner: 'eui' },
  ],
  mounts: { eui: '/EUI', xui: '/XUI' },
  currentOwner: 'eui',
}

describe('createCrossLinkResolver', () => {
  const resolve = createCrossLinkResolver(config)

  it('resolves a current-owner route to an in-app, root-relative href', () => {
    expect(resolve('dashboard')).toEqual({ sameApp: true, href: '/dashboard' })
  })

  it('resolves an other-owner route to a full-page href on that app mount', () => {
    expect(resolve('login')).toEqual({ sameApp: false, href: '/XUI/login' })
  })

  it('matches "*" wildcard patterns one segment at a time', () => {
    expect(resolve('realms/alpha/authentication')).toEqual({
      sameApp: false,
      href: '/XUI/realms/alpha/authentication',
    })
  })

  it('lets a parent route own its unenumerated sub-paths (prefix match)', () => {
    expect(resolve('realms/alpha')).toEqual({ sameApp: false, href: '/XUI/realms/alpha' })
  })

  it('owns deep-links below a wildcard pattern, not just exact-depth paths', () => {
    expect(resolve('realms/alpha/authentication/trees/Custom')).toEqual({
      sameApp: false,
      href: '/XUI/realms/alpha/authentication/trees/Custom',
    })
  })

  it('prefers the most specific (deepest) matching route over a parent route', () => {
    // "realms" is xui but the deeper "realms/*/sessions" is eui -> in-app wins.
    expect(resolve('realms/beta/sessions')).toEqual({ sameApp: true, href: '/realms/beta/sessions' })
  })

  it('carries a query string through to the resolved cross-app href', () => {
    expect(resolve('login?goto=%2Fhome&realm=%2F')).toEqual({
      sameApp: false,
      href: '/XUI/login?goto=%2Fhome&realm=%2F',
    })
  })

  it('carries a hash fragment through to the resolved same-app href', () => {
    expect(resolve('dashboard#widgets')).toEqual({ sameApp: true, href: '/dashboard#widgets' })
  })

  it('treats an unmatched route as in-app (react-router will 404 if unknown)', () => {
    expect(resolve('totally/unknown')).toEqual({ sameApp: true, href: '/totally/unknown' })
  })

  it('normalizes a leading slash on the target', () => {
    expect(resolve('/dashboard')).toEqual({ sameApp: true, href: '/dashboard' })
  })

  it('throws when the owning app has no configured mount', () => {
    const broken = createCrossLinkResolver({ ...config, mounts: { eui: '/EUI' } })
    expect(() => broken('login')).toThrow(/no mount configured for owner "xui"/)
  })
})
