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
import { DEMO_TOKEN_ID } from '../fixtures/authenticate.ts'
import { DEMO_SESSION, LOGOUT_RESULT } from '../fixtures/sessions.ts'

function isValidToken(request: Request): boolean {
  const tokenId = new URL(request.url).searchParams.get('tokenId')
  return tokenId === DEMO_TOKEN_ID
}

export const sessionsHandlers: RequestHandler[] = [
  http.get('*/json/sessions', ({ request }) => {
    if (!isValidToken(request)) {
      return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'Invalid session' }, { status: 401 })
    }
    return HttpResponse.json(DEMO_SESSION)
  }),

  http.head('*/json/sessions', ({ request }) => {
    if (!isValidToken(request)) {
      return new HttpResponse(null, { status: 401 })
    }
    return new HttpResponse(null, { status: 200 })
  }),

  http.post('*/json/sessions', ({ request }) => {
    const action = new URL(request.url).searchParams.get('_action')
    // getSessionInfo: used by the legacy XUI on bootstrap to check for an existing session.
    // No valid token → 401 so the XUI falls through to the login screen.
    if (action === 'getSessionInfo') {
      const tokenId = new URL(request.url).searchParams.get('tokenId')
      if (tokenId !== DEMO_TOKEN_ID) {
        return HttpResponse.json({ code: 401, reason: 'Unauthorized', message: 'No valid session' }, { status: 401 })
      }
      return HttpResponse.json(DEMO_SESSION)
    }
    // Default: logout
    return HttpResponse.json(LOGOUT_RESULT)
  }),
]
