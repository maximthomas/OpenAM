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

import { http, HttpResponse } from 'msw'
import type { RequestHandler } from 'msw'
import type { AmAuthChallenge } from '../types.ts'
import {
  AUTH_CHALLENGE,
  AUTH_CHALLENGE_PASSWORD_STAGE,
  AUTH_CHALLENGE_USERNAME_STAGE,
  AUTH_ERROR,
  AUTH_ID,
  AUTH_SUCCESS,
  MULTI_AUTH_ID_1,
  MULTI_AUTH_ID_2,
} from '../fixtures/authenticate.ts'

/**
 * Core state-machine dispatch: given a parsed request body, returns the next AM response.
 * Exported so tests can install it as the initial handler when exercising multi-stage flows.
 */
export function resolveAuthenticateBody(body: Partial<AmAuthChallenge>): Response {
  const { authId, callbacks } = body

  // Initial request (no authId) → default single-stage challenge.
  if (!authId) {
    return HttpResponse.json(AUTH_CHALLENGE)
  }

  // Single-stage path: both NameCallback and PasswordCallback in one challenge.
  if (authId === AUTH_ID) {
    const name = callbacks?.find((cb) => cb.type === 'NameCallback')?.input[0]?.value
    const password = callbacks?.find((cb) => cb.type === 'PasswordCallback')?.input[0]?.value
    if (name === 'demo' && password === 'changeit') {
      return HttpResponse.json(AUTH_SUCCESS)
    }
    return HttpResponse.json(AUTH_ERROR, { status: 401 })
  }

  // Multi-stage path — stage 1: username only → validate, return password stage.
  if (authId === MULTI_AUTH_ID_1) {
    const name = callbacks?.find((cb) => cb.type === 'NameCallback')?.input[0]?.value
    if (name === 'demo') {
      return HttpResponse.json(AUTH_CHALLENGE_PASSWORD_STAGE)
    }
    return HttpResponse.json(AUTH_ERROR, { status: 401 })
  }

  // Multi-stage path — stage 2: password only → validate, return success.
  if (authId === MULTI_AUTH_ID_2) {
    const password = callbacks?.find((cb) => cb.type === 'PasswordCallback')?.input[0]?.value
    if (password === 'changeit') {
      return HttpResponse.json(AUTH_SUCCESS)
    }
    return HttpResponse.json(AUTH_ERROR, { status: 401 })
  }

  // Unknown authId.
  return HttpResponse.json(AUTH_ERROR, { status: 401 })
}

async function resolveAuthenticate(request: Request): Promise<Response> {
  const text = await request.text()
  const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
  return resolveAuthenticateBody(body)
}

/**
 * Multi-stage authenticate handler for use in tests via server.use().
 * Overrides the initial (no-authId) response to return the username-only stage 1 challenge;
 * subsequent stages are handled by the regular state machine (resolveAuthenticateBody).
 */
export async function multiStageAuthenticateHandler(request: Request): Promise<Response> {
  const text = await request.text()
  const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
  if (!body.authId) {
    return HttpResponse.json(AUTH_CHALLENGE_USERNAME_STAGE)
  }
  return resolveAuthenticateBody(body)
}

export const authenticateHandlers: RequestHandler[] = [
  http.post('*/json/authenticate', ({ request }) => resolveAuthenticate(request)),
  http.post('*/json/realms/root/authenticate', ({ request }) => resolveAuthenticate(request)),
]
