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

import type { AmLogoutResult, AmSessionInfo } from '../types.ts'

export const DEMO_SESSION: AmSessionInfo = {
  username: 'demo',
  universalId: 'id=demo,ou=user,dc=openam,dc=openidentityplatform,dc=org',
  realm: '/',
  latestAccessTime: '2026-06-29T00:00:00Z',
  maxSessionExpirationTime: '2026-06-29T02:00:00Z',
  maxIdleExpirationTime: '2026-06-29T00:30:00Z',
  properties: {},
}

export const LOGOUT_RESULT: AmLogoutResult = {
  result: true,
}

// A token the mock does not recognize, so getSessionInfo/isSessionValid treat it as an
// already-invalidated session (401) — mirrors real AM once a session has actually timed out.
// Used by useSessionMonitor.test.ts / SessionGuard*.test.tsx (P1-5k) to drive expiry
// deterministically.
export const EXPIRING_TOKEN_ID = 'expiring-session-token-id'
