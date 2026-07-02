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

/** Exported so tests can drive allowed/rejected scenarios directly. */
export const MOCK_GOTO_ALLOWED = 'http://allowed.example.com/dashboard'
export const MOCK_GOTO_REJECTED = 'http://open-redirect.evil.com'

function isGotoAllowed(goto: string): boolean {
  // Relative paths (starting with /) are always allowed.
  if (goto.startsWith('/')) return true
  // Localhost on any port.
  if (/^https?:\/\/localhost(:\d+)?/.test(goto)) return true
  // Explicit allowlist for mock scenarios.
  if (goto === MOCK_GOTO_ALLOWED) return true
  return false
}

async function handleUsersAction(request: Request): Promise<Response> {
  const url = new URL(request.url)
  const action = url.searchParams.get('_action')

  if (action !== 'validateGoto') {
    return HttpResponse.json({ code: 404, reason: 'Not Found', message: 'Not Found' }, { status: 404 })
  }

  const body = (await request.json()) as { goto?: string }
  const goto = body.goto ?? ''

  if (!isGotoAllowed(goto)) {
    return HttpResponse.json(
      { code: 400, reason: 'Bad Request', message: 'goto parameter is not valid' },
      { status: 400 },
    )
  }

  return HttpResponse.json({ successURL: goto })
}

export const usersHandlers: RequestHandler[] = [
  http.post('*/json/users', ({ request }) => handleUsersAction(request)),
  http.post('*/json/realms/root/users', ({ request }) => handleUsersAction(request)),
]
