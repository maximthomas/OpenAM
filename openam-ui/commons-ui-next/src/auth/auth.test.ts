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
import { DEMO_TOKEN_ID } from '../mock/index.ts'
import { createFetchTransport } from '../transport.ts'
import { startAuthentication, submitCallbacks, fillCallbacks, isAuthSuccess, isAuthFailure } from './authenticate.ts'

// MSW intercepts fetch for any hostname; use a recognisable test origin.
const transport = createFetchTransport({ baseUrl: 'http://openam.test' })

describe('authenticate', () => {
  it('startAuthentication returns a requirements step with NameCallback and PasswordCallback', async () => {
    const step = await startAuthentication(transport)
    expect(step.kind).toBe('requirements')
    if (step.kind !== 'requirements') return
    expect(step.challenge.authId).toBeTruthy()
    const types = step.challenge.callbacks.map((cb) => cb.type)
    expect(types).toContain('NameCallback')
    expect(types).toContain('PasswordCallback')
  })

  it('submitCallbacks with correct credentials returns a success step with tokenId', async () => {
    const challenge = await startAuthentication(transport)
    expect(challenge.kind).toBe('requirements')
    if (challenge.kind !== 'requirements') return

    const filled = fillCallbacks(challenge.challenge, ['demo', 'changeit'])
    const step = await submitCallbacks(transport, filled)

    expect(isAuthSuccess(step)).toBe(true)
    if (!isAuthSuccess(step)) return
    expect(step.success.tokenId).toBe(DEMO_TOKEN_ID)
  })

  it('submitCallbacks with wrong credentials returns a failure step (not thrown)', async () => {
    const challenge = await startAuthentication(transport)
    expect(challenge.kind).toBe('requirements')
    if (challenge.kind !== 'requirements') return

    const filled = fillCallbacks(challenge.challenge, ['wrong', 'credentials'])
    const step = await submitCallbacks(transport, filled)

    expect(isAuthFailure(step)).toBe(true)
    if (!isAuthFailure(step)) return
    expect(step.error.code).toBe(401)
  })

  it('fillCallbacks populates all callback inputs in order and is immutable', () => {
    const challenge = {
      authId: 'test',
      template: '',
      stage: '',
      header: '',
      callbacks: [
        { type: 'NameCallback' as const, output: [], input: [{ name: 'IDToken1', value: '' }] },
        { type: 'PasswordCallback' as const, output: [], input: [{ name: 'IDToken2', value: '' }] },
      ],
    }
    const filled = fillCallbacks(challenge, ['alice', 'secret'])
    expect(filled.callbacks[0].input[0].value).toBe('alice')
    expect(filled.callbacks[1].input[0].value).toBe('secret')
    expect(challenge.callbacks[0].input[0].value).toBe('')
  })
})
