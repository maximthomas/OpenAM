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
import { getBasename } from './runtime'

describe('getBasename (path-relocatable mount, ADR-0004)', () => {
  afterEach(() => {
    delete window.__EUI_RUNTIME__
    document.head.querySelector('base')?.remove()
  })

  it('defaults to "/" when nothing is configured (dev / mock)', () => {
    expect(getBasename()).toBe('/')
  })

  it('derives the basename from the document <base href>, stripping a trailing slash', () => {
    setBaseHref('/EUI/')
    expect(getBasename()).toBe('/EUI')
  })

  it('serves the same build from a different mount (/XUI after cutover)', () => {
    setBaseHref('/XUI/')
    expect(getBasename()).toBe('/XUI')
  })

  it('uses the __EUI_RUNTIME__ escape hatch when there is no <base href>', () => {
    window.__EUI_RUNTIME__ = { basename: '/EUI/' }
    expect(getBasename()).toBe('/EUI')
  })

  it('lets <base href> win over the escape hatch so assets and routing stay in sync', () => {
    setBaseHref('/EUI/')
    window.__EUI_RUNTIME__ = { basename: '/XUI' }
    expect(getBasename()).toBe('/EUI')
  })
})

function setBaseHref(href: string): void {
  const base = document.createElement('base')
  base.setAttribute('href', href)
  document.head.appendChild(base)
}
