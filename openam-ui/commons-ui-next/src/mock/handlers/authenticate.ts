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
  AUTH_CHALLENGE_POLLING_1,
  AUTH_CHALLENGE_POLLING_2,
  AUTH_CHALLENGE_REDIRECT_GET,
  AUTH_CHALLENGE_SCRIPT_TEXT_OUTPUT,
  AUTH_CHALLENGE_USERNAME_STAGE,
  AUTH_ERROR,
  AUTH_ID,
  AUTH_SUCCESS,
  AUTH_SUCCESS_OTHER_REALM,
  AUTH_TIMEOUT_ERROR,
  MULTI_AUTH_ID_1,
  MULTI_AUTH_ID_2,
  POLLING_AUTH_ID_1,
  POLLING_AUTH_ID_2,
  REDIRECT_GET_AUTH_ID,
  REDIRECT_POST_AUTH_ID,
  SCRIPT_TEXT_OUTPUT_AUTH_ID,
  SCRIPT_TEXT_OUTPUT_RESULT,
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

  // Redirect path — after the browser is sent to the IdP and comes back, AM returns success.
  if (authId === REDIRECT_GET_AUTH_ID || authId === REDIRECT_POST_AUTH_ID) {
    return HttpResponse.json(AUTH_SUCCESS)
  }

  // Polling path — two poll stages, then success.
  if (authId === POLLING_AUTH_ID_1) {
    return HttpResponse.json(AUTH_CHALLENGE_POLLING_2)
  }
  if (authId === POLLING_AUTH_ID_2) {
    return HttpResponse.json(AUTH_SUCCESS)
  }

  // Script-text-output path (P1-5g) — succeed once the script-computed hidden value comes back.
  if (authId === SCRIPT_TEXT_OUTPUT_AUTH_ID) {
    const hiddenValue = callbacks?.find((cb) => cb.type === 'HiddenValueCallback')?.input[0]?.value
    if (hiddenValue === SCRIPT_TEXT_OUTPUT_RESULT) {
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

/**
 * Redirect authenticate handler — initial call returns a GET redirect challenge.
 * Use in tests via server.use() to exercise the redirect intercept path.
 */
export async function redirectAuthenticateHandler(request: Request): Promise<Response> {
  const text = await request.text()
  const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
  if (!body.authId) {
    return HttpResponse.json(AUTH_CHALLENGE_REDIRECT_GET)
  }
  return resolveAuthenticateBody(body)
}

/**
 * Polling authenticate handler — initial call returns the first polling stage.
 * Two auto-submits later the flow resolves to success.
 * Use in tests via server.use() to exercise the polling auto-submit path.
 */
export async function pollingAuthenticateHandler(request: Request): Promise<Response> {
  const text = await request.text()
  const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
  if (!body.authId) {
    return HttpResponse.json(AUTH_CHALLENGE_POLLING_1)
  }
  return resolveAuthenticateBody(body)
}

/**
 * 408 authenticate handler — returns a valid challenge first, then a 408 timeout, then
 * a fresh challenge (simulating the restart-after-timeout flow).
 * Use in tests via server.use() with a call counter to exercise the 408 retry path.
 */
export function make408ThenRecoverHandler() {
  let callCount = 0
  return async (request: Request): Promise<Response> => {
    const text = await request.text()
    const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
    callCount++
    if (callCount === 1) return HttpResponse.json(AUTH_CHALLENGE) // initial challenge
    if (callCount === 2 && body.authId === AUTH_ID)
      return HttpResponse.json(AUTH_TIMEOUT_ERROR, { status: 408 }) // timeout on submit
    return resolveAuthenticateBody({ ...body, authId: undefined }) // restart → fresh challenge
  }
}

/**
 * Zero-page reject handler — returns AUTH_CHALLENGE for the initial (no-authId) request,
 * and AUTH_ERROR 401 for any submit (authId present). Subsequent restarts return AUTH_CHALLENGE.
 * Use in tests via server.use() to verify the zero-page path does not retry on credential failure.
 */
export function makeZeroPageRejectHandler() {
  return async (request: Request): Promise<Response> => {
    const text = await request.text()
    const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
    if (body.authId) {
      return HttpResponse.json(AUTH_ERROR, { status: 401 })
    }
    return HttpResponse.json(AUTH_CHALLENGE)
  }
}

/**
 * Script-text-output authenticate handler — initial call returns the HiddenValueCallback +
 * ScriptTextOutputCallback stage (P1-5g). Use in tests via server.use() to exercise the script
 * execution + write-back path.
 */
export async function scriptTextOutputAuthenticateHandler(request: Request): Promise<Response> {
  const text = await request.text()
  const body = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>
  if (!body.authId) {
    return HttpResponse.json(AUTH_CHALLENGE_SCRIPT_TEXT_OUTPUT)
  }
  return resolveAuthenticateBody(body)
}

/**
 * Existing-session handler — initial /authenticate (no authId) immediately returns success.
 * Use in tests via server.use() to simulate a user with a live session visiting /login.
 */
export async function existingSessionAuthenticateHandler(): Promise<Response> {
  return HttpResponse.json(AUTH_SUCCESS)
}

/**
 * Existing-session handler for a different-realm scenario — same as above but realm differs.
 * Navigate to /confirmLogin when the URL realm doesn't match the session realm.
 */
export async function existingSessionOtherRealmHandler(): Promise<Response> {
  return HttpResponse.json(AUTH_SUCCESS_OTHER_REALM)
}

export const authenticateHandlers: RequestHandler[] = [
  http.post('*/json/authenticate', ({ request }) => resolveAuthenticate(request)),
  http.post('*/json/realms/root/authenticate', ({ request }) => resolveAuthenticate(request)),
]
