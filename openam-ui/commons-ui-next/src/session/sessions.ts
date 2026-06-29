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
import type { AmLogoutResult, AmSessionInfo } from './types.ts'

const SESSION_VERSION = 'protocol=1.0,resource=2.0'

export async function getSessionInfo(transport: Transport, token: string): Promise<AmSessionInfo> {
  const res = await transport(`/sessions?_action=getSessionInfo&tokenId=${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: { 'Accept-API-Version': SESSION_VERSION },
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`getSessionInfo failed: ${res.status} ${body}`)
  }
  return res.json() as Promise<AmSessionInfo>
}

// Returns false on any error (including 401) so callers can use it as a guard without try/catch.
export async function isSessionValid(transport: Transport, token: string): Promise<boolean> {
  try {
    const info = await getSessionInfo(transport, token)
    return 'username' in info
  } catch {
    return false
  }
}

// Seconds until the session expires — min of idle and max session expiry.
export async function getTimeLeft(transport: Transport, token: string): Promise<number> {
  const info = await getSessionInfo(transport, token)
  const idle = Math.floor((new Date(info.maxIdleExpirationTime).getTime() - Date.now()) / 1000)
  const max = Math.floor((new Date(info.maxSessionExpirationTime).getTime() - Date.now()) / 1000)
  return Math.min(idle, max)
}

export async function logout(transport: Transport, token: string): Promise<AmLogoutResult> {
  const res = await transport(`/sessions?_action=logout&tokenId=${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: { 'Accept-API-Version': SESSION_VERSION },
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`logout failed: ${res.status} ${body}`)
  }
  return res.json() as Promise<AmLogoutResult>
}
