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
import { AUTH_CHALLENGE, AUTH_ERROR, AUTH_SUCCESS } from '../fixtures/authenticate.ts'

async function resolveAuthenticate(request: Request): Promise<Response> {
  const text = await request.text()
  const json = (text ? JSON.parse(text) : {}) as Partial<AmAuthChallenge>

  if (!json.authId) {
    return HttpResponse.json(AUTH_CHALLENGE)
  }

  const name = json.callbacks?.find((cb) => cb.type === 'NameCallback')?.input[0]?.value
  const password = json.callbacks?.find((cb) => cb.type === 'PasswordCallback')?.input[0]?.value

  if (name === 'demo' && password === 'changeit') {
    return HttpResponse.json(AUTH_SUCCESS)
  }

  return HttpResponse.json(AUTH_ERROR, { status: 401 })
}

export const authenticateHandlers: RequestHandler[] = [
  http.post('*/json/authenticate', ({ request }) => resolveAuthenticate(request)),
  http.post('*/json/realms/root/authenticate', ({ request }) => resolveAuthenticate(request)),
]
