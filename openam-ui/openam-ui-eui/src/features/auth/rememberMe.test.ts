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

import { afterEach, describe, expect, it } from 'vitest'
import { clearRememberedLogin, getRememberedLogin, setRememberedLogin } from './rememberMe.ts'

describe('rememberMe', () => {
  afterEach(() => {
    // jsdom does not reset document.cookie between tests — clear it explicitly.
    document.cookie = 'login=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
  })

  it('returns undefined when no login cookie is set', () => {
    expect(getRememberedLogin()).toBeUndefined()
  })

  it('round-trips a remembered username', () => {
    setRememberedLogin('alice')
    expect(getRememberedLogin()).toBe('alice')
  })

  it('clears the remembered username', () => {
    setRememberedLogin('alice')
    clearRememberedLogin()
    expect(getRememberedLogin()).toBeUndefined()
  })

  it('sets a 20-day expiry', () => {
    setRememberedLogin('alice')
    expect(document.cookie).toContain('login=alice')
  })
})
