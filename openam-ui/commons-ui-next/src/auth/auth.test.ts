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
import { http } from 'msw'
import { DEMO_TOKEN_ID, multiStageAuthenticateHandler, REDIRECT_POST_AUTH_ID } from '../mock/index.ts'
import { server } from '../test/setup.ts'
import { createFetchTransport } from '../transport.ts'
import {
  startAuthentication,
  resumeAuthentication,
  submitCallbacks,
  fillCallbacks,
  setCallbackValue,
  isAuthSuccess,
  isAuthFailure,
} from './authenticate.ts'

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

  it('multi-stage flow: username stage → password stage → success', async () => {
    server.use(http.post('*/json/authenticate', ({ request }) => multiStageAuthenticateHandler(request)))
    server.use(http.post('*/json/realms/root/authenticate', ({ request }) => multiStageAuthenticateHandler(request)))

    // Stage 1: username only
    const stage1 = await startAuthentication(transport)
    expect(stage1.kind).toBe('requirements')
    if (stage1.kind !== 'requirements') return
    const s1Types = stage1.challenge.callbacks.map((cb) => cb.type)
    expect(s1Types).toEqual(['NameCallback'])

    // Submit stage 1 with correct username → password stage
    const filled1 = setCallbackValue(stage1.challenge, 0, 'demo')
    const stage2 = await submitCallbacks(transport, filled1)
    expect(stage2.kind).toBe('requirements')
    if (stage2.kind !== 'requirements') return
    const s2Types = stage2.challenge.callbacks.map((cb) => cb.type)
    expect(s2Types).toEqual(['PasswordCallback'])

    // Submit stage 2 with correct password → success
    const filled2 = setCallbackValue(stage2.challenge, 0, 'changeit')
    const result = await submitCallbacks(transport, filled2)
    expect(isAuthSuccess(result)).toBe(true)
    if (!isAuthSuccess(result)) return
    expect(result.success.tokenId).toBe(DEMO_TOKEN_ID)
  })

  it('multi-stage flow: wrong username returns failure', async () => {
    server.use(http.post('*/json/authenticate', ({ request }) => multiStageAuthenticateHandler(request)))
    server.use(http.post('*/json/realms/root/authenticate', ({ request }) => multiStageAuthenticateHandler(request)))

    const stage1 = await startAuthentication(transport)
    expect(stage1.kind).toBe('requirements')
    if (stage1.kind !== 'requirements') return

    const filled1 = setCallbackValue(stage1.challenge, 0, 'wrong-user')
    const result = await submitCallbacks(transport, filled1)
    expect(isAuthFailure(result)).toBe(true)
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

  it('resumeAuthentication posts a bare authId and resolves the tracked redirect flow', async () => {
    const step = await resumeAuthentication(transport, REDIRECT_POST_AUTH_ID)
    expect(isAuthSuccess(step)).toBe(true)
    if (!isAuthSuccess(step)) return
    expect(step.success.tokenId).toBe(DEMO_TOKEN_ID)
  })

  it('resumeAuthentication with an unknown authId returns a failure step', async () => {
    const step = await resumeAuthentication(transport, 'not-a-tracked-authId')
    expect(isAuthFailure(step)).toBe(true)
  })
})
