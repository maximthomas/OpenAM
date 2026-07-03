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

import { describe, expect, it } from 'vitest'
import {
  AUTH_CHALLENGE,
  AUTH_SUCCESS,
  DEMO_TOKEN_ID,
  SERVER_INFO,
  LOGOUT_RESULT,
  DEMO_SESSION,
} from '@openidentityplatform/commons-ui-next/mock'

const AM = 'http://openam.example.com/openam'

describe('authenticate handler', () => {
  it('step 1 — no body returns challenge', async () => {
    const res = await fetch(`${AM}/json/authenticate`, { method: 'POST' })
    expect(res.status).toBe(200)
    const body = await res.json() as typeof AUTH_CHALLENGE
    expect(body.authId).toBe(AUTH_CHALLENGE.authId)
    expect(body.stage).toBe('DataStore1')
  })

  it('step 2 — correct credentials return success', async () => {
    const challenge = { ...AUTH_CHALLENGE, callbacks: [
      { type: 'NameCallback' as const, output: [], input: [{ name: 'IDToken1', value: 'demo' }] },
      { type: 'PasswordCallback' as const, output: [], input: [{ name: 'IDToken2', value: 'changeit' }] },
    ]}
    const res = await fetch(`${AM}/json/authenticate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(challenge),
    })
    expect(res.status).toBe(200)
    const body = await res.json() as typeof AUTH_SUCCESS
    expect(body.tokenId).toBe(AUTH_SUCCESS.tokenId)
  })

  it('step 2 — wrong credentials return 401', async () => {
    const challenge = { ...AUTH_CHALLENGE, callbacks: [
      { type: 'NameCallback' as const, output: [], input: [{ name: 'IDToken1', value: 'wrong' }] },
      { type: 'PasswordCallback' as const, output: [], input: [{ name: 'IDToken2', value: 'wrong' }] },
    ]}
    const res = await fetch(`${AM}/json/authenticate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(challenge),
    })
    expect(res.status).toBe(401)
    const body = await res.json() as { code: number }
    expect(body.code).toBe(401)
  })
})

describe('serverinfo handler', () => {
  it('returns server info for any attribute path', async () => {
    const res = await fetch(`${AM}/json/serverinfo/cookieName`)
    expect(res.status).toBe(200)
    const body = await res.json() as typeof SERVER_INFO
    expect(body.cookieName).toBe(SERVER_INFO.cookieName)
    expect(body.realm).toBe(SERVER_INFO.realm)
  })
})

describe('sessions handler', () => {
  it('HEAD with valid tokenId returns 200', async () => {
    const res = await fetch(`${AM}/json/sessions?tokenId=${encodeURIComponent(DEMO_TOKEN_ID)}`, { method: 'HEAD' })
    expect(res.status).toBe(200)
  })

  it('HEAD with invalid tokenId returns 401', async () => {
    const res = await fetch(`${AM}/json/sessions?tokenId=invalid`, { method: 'HEAD' })
    expect(res.status).toBe(401)
  })

  it('GET with valid tokenId returns session info', async () => {
    const res = await fetch(`${AM}/json/sessions?tokenId=${encodeURIComponent(DEMO_TOKEN_ID)}`)
    expect(res.status).toBe(200)
    const body = await res.json() as typeof DEMO_SESSION
    expect(body.username).toBe(DEMO_SESSION.username)
  })

  it('POST logout returns result true', async () => {
    const res = await fetch(`${AM}/json/sessions?_action=logout`, { method: 'POST' })
    expect(res.status).toBe(200)
    const body = await res.json() as typeof LOGOUT_RESULT
    expect(body.result).toBe(LOGOUT_RESULT.result)
  })
})
