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

export type { Transport }

/**
 * Resolve the /json path segment for a given realm.
 *
 * realm: false  → ""                                (no realm prefix)
 * realm: "/"    → "/realms/root"                    (root realm)
 * realm: "/sub" → "/realms/root/realms/sub"         (absolute sub-realm)
 * realm: "alias"→ "/realms/alias"                   (realm alias, no leading slash)
 *
 * Algorithm matches the legacy fetchUrl.jsm:
 *   "/" is a special case → "/root"; all other absolute realms get "/root" prepended.
 *   Then every "/" in that intermediate string is replaced with "/realms/".
 */
export function resolveRealmPath(realm: string | false, path: string): string {
  if (realm === false) return path

  let realmSegment: string
  if (realm.startsWith('/')) {
    const withRoot = realm === '/' ? '/root' : '/root' + realm
    realmSegment = withRoot.replace(/\//g, '/realms/')
  } else {
    realmSegment = '/realms/' + realm
  }

  return realmSegment + path
}

export class AmApiError extends Error {
  readonly status: number
  readonly code: number
  readonly reason: string

  constructor(status: number, code: number, reason: string, message: string) {
    super(message)
    this.name = 'AmApiError'
    this.status = status
    this.code = code
    this.reason = reason
  }
}

/** Parse AM's { code, reason, message } error body into an AmApiError. */
export async function parseAmError(res: Response): Promise<AmApiError> {
  let body: { code?: number; reason?: string; message?: string } = {}
  try {
    body = (await res.json()) as typeof body
  } catch {
    // non-JSON body — fall through to defaults
  }
  return new AmApiError(
    res.status,
    body.code ?? res.status,
    body.reason ?? res.statusText,
    body.message ?? `AM request failed: ${res.status} ${res.statusText}`,
  )
}

/**
 * Real AM REST transport factory.
 *
 * Produces URLs: ${baseUrl}/json${resolvedRealm}${path}
 * Always sends credentials (iPlanetDirectoryPro cookie).
 * Returns the raw Response — callers own error handling.
 */
export function createAmTransport(opts: { baseUrl: string; realm?: string | false }): Transport {
  const base = opts.baseUrl.replace(/\/$/, '')
  const realm = opts.realm === undefined ? '/' : opts.realm

  return (path, init) => {
    const url = base + '/json' + resolveRealmPath(realm, path)
    return fetch(url, { credentials: 'include', ...init })
  }
}
