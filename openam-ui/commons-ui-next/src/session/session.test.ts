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

import { describe, expect, it, afterEach, vi } from 'vitest'
import { DEMO_TOKEN_ID, DEMO_SESSION } from '../mock/index.ts'
import { createFetchTransport } from '../transport.ts'
import { getSessionInfo, isSessionValid, getTimeLeft, logout } from './sessions.ts'

// MSW intercepts fetch for any hostname; use a recognisable test origin.
const transport = createFetchTransport({ baseUrl: 'http://openam.test' })

describe('sessions', () => {
  it('getSessionInfo returns session data for a valid token', async () => {
    const info = await getSessionInfo(transport, DEMO_TOKEN_ID)
    expect(info).toMatchObject({
      username: DEMO_SESSION.username,
      realm: DEMO_SESSION.realm,
    })
  })

  it('getSessionInfo throws for an invalid token', async () => {
    await expect(getSessionInfo(transport, 'bad-token')).rejects.toThrow()
  })

  it('isSessionValid returns true for a valid token', async () => {
    expect(await isSessionValid(transport, DEMO_TOKEN_ID)).toBe(true)
  })

  it('isSessionValid returns false for an invalid token without throwing', async () => {
    expect(await isSessionValid(transport, 'bad-token')).toBe(false)
  })

  it('getTimeLeft returns the remaining seconds (positive for a future expiry)', async () => {
    // Freeze time to before the fixture expiry timestamps so the result is positive.
    // maxIdleExpirationTime  = '2026-06-29T00:30:00Z' → 1800s from anchor
    // maxSessionExpirationTime = '2026-06-29T02:00:00Z' → 7200s from anchor
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-06-29T00:00:00Z'))
    try {
      const seconds = await getTimeLeft(transport, DEMO_TOKEN_ID)
      expect(seconds).toBe(1800) // min(1800, 7200)
    } finally {
      vi.useRealTimers()
    }
  })

  it('logout returns result:true', async () => {
    const result = await logout(transport, DEMO_TOKEN_ID)
    expect(result).toEqual({ result: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })
})
