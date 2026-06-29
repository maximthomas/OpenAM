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

import type { Transport } from '../transport.ts'
import type { AmAuthChallenge } from '../auth/types.ts'
import { startAuthentication, submitCallbacks } from '../auth/authenticate.ts'
import { getSessionInfo, isSessionValid, getTimeLeft, logout } from './sessions.ts'
import { getToken, setToken, clearToken } from './token.ts'

// Convenience factory: bind the transport once, use the in-memory token holder for
// session-scoped calls. Consumers that need the raw functions can import them directly.
export function createSessionService(transport: Transport) {
  function requireToken(): string {
    const t = getToken()
    if (t === undefined) throw new Error('No active session token')
    return t
  }

  return {
    startAuthentication: () => startAuthentication(transport),
    submitCallbacks: (challenge: AmAuthChallenge) => submitCallbacks(transport, challenge),
    getToken,
    setToken,
    clearToken,
    getSessionInfo: () => getSessionInfo(transport, requireToken()),
    isSessionValid: () => {
      const t = getToken()
      if (t === undefined) return Promise.resolve(false)
      return isSessionValid(transport, t)
    },
    getTimeLeft: () => getTimeLeft(transport, requireToken()),
    logout: () => logout(transport, requireToken()),
  }
}

export type SessionService = ReturnType<typeof createSessionService>
