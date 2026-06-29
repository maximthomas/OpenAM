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
import { http, HttpResponse } from 'msw'
import { server } from '../test/setup.ts'
import { resolveRealmPath, AmApiError, parseAmError, createAmTransport } from './index.ts'

// --- resolveRealmPath (pure) ---

describe('resolveRealmPath', () => {
  it('false → no realm prefix', () => {
    expect(resolveRealmPath(false, '/authenticate')).toBe('/authenticate')
  })

  it('"/" → /realms/root', () => {
    expect(resolveRealmPath('/', '/authenticate')).toBe('/realms/root/authenticate')
  })

  it('"/sub" → /realms/root/realms/sub', () => {
    expect(resolveRealmPath('/sub', '/authenticate')).toBe('/realms/root/realms/sub/authenticate')
  })

  it('"/a/b" → /realms/root/realms/a/realms/b', () => {
    expect(resolveRealmPath('/a/b', '/x')).toBe('/realms/root/realms/a/realms/b/x')
  })

  it('"alias" (no slash) → /realms/alias', () => {
    expect(resolveRealmPath('alias', '/authenticate')).toBe('/realms/alias/authenticate')
  })
})

// --- AmApiError ---

describe('AmApiError', () => {
  it('is an Error with the expected properties', () => {
    const err = new AmApiError(401, 401, 'Unauthorized', 'Authentication Failed!!')
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('AmApiError')
    expect(err.status).toBe(401)
    expect(err.code).toBe(401)
    expect(err.reason).toBe('Unauthorized')
    expect(err.message).toBe('Authentication Failed!!')
  })
})

// --- parseAmError ---

describe('parseAmError', () => {
  it('parses AM JSON error body', async () => {
    const res = new Response(JSON.stringify({ code: 401, reason: 'Unauthorized', message: 'Bad creds' }), {
      status: 401,
    })
    const err = await parseAmError(res)
    expect(err).toBeInstanceOf(AmApiError)
    expect(err.status).toBe(401)
    expect(err.code).toBe(401)
    expect(err.reason).toBe('Unauthorized')
    expect(err.message).toBe('Bad creds')
  })

  it('falls back gracefully when body is not JSON', async () => {
    const res = new Response('Internal Server Error', { status: 500, statusText: 'Internal Server Error' })
    const err = await parseAmError(res)
    expect(err.status).toBe(500)
    expect(err.code).toBe(500)
  })
})

// --- createAmTransport ---

describe('createAmTransport', () => {
  it('default realm (/) sends request to /json/realms/root/...', async () => {
    let capturedUrl = ''
    server.use(
      http.post('*/json/realms/root/authenticate', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({})
      }),
    )

    const transport = createAmTransport({ baseUrl: 'http://openam.test' })
    await transport('/authenticate', { method: 'POST' })
    expect(capturedUrl).toContain('/json/realms/root/authenticate')
  })

  it('realm: false sends request to /json/... (no realm prefix)', async () => {
    let capturedUrl = ''
    server.use(
      http.post('*/json/authenticate', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({})
      }),
    )

    const transport = createAmTransport({ baseUrl: 'http://openam.test', realm: false })
    await transport('/authenticate', { method: 'POST' })
    expect(capturedUrl).toContain('/json/authenticate')
    expect(capturedUrl).not.toContain('/realms/')
  })

  it('sends credentials: include', async () => {
    let capturedCredentials: RequestCredentials | undefined
    server.use(
      http.post('*/json/realms/root/authenticate', ({ request }) => {
        capturedCredentials = request.credentials
        return HttpResponse.json({})
      }),
    )

    const transport = createAmTransport({ baseUrl: 'http://openam.test' })
    await transport('/authenticate', { method: 'POST' })
    expect(capturedCredentials).toBe('include')
  })

  it('caller-supplied init is merged (not overwritten)', async () => {
    let capturedMethod = ''
    server.use(
      http.post('*/json/realms/root/authenticate', ({ request }) => {
        capturedMethod = request.method
        return HttpResponse.json({})
      }),
    )

    const transport = createAmTransport({ baseUrl: 'http://openam.test' })
    await transport('/authenticate', { method: 'POST', headers: { 'Accept-API-Version': 'protocol=1.0,resource=2.1' } })
    expect(capturedMethod).toBe('POST')
  })

  it('returns the Response unchanged (does not throw on 401)', async () => {
    server.use(
      http.post('*/json/realms/root/authenticate', () => {
        return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'Bad creds' }, { status: 401 })
      }),
    )

    const transport = createAmTransport({ baseUrl: 'http://openam.test' })
    const res = await transport('/authenticate', { method: 'POST' })
    expect(res.status).toBe(401)
    expect(res.ok).toBe(false)
  })
})
