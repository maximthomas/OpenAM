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

// AuthNService.js / AuthenticationToken.jsm port (P1-5i): tracks the AM `authId` while a
// federated (RedirectCallback) round-trip is in flight, so a return visit can resume the flow
// instead of restarting it. Uses the legacy cookie name ("authId") for cross-app (XUI/EUI)
// coexistence interop — same precedent as P1-5f's `login` remember-me cookie.

const COOKIE_NAME = 'authId'

export type TrackingCookieOptions = {
  /** cookieDomains from serverinfo — one cookie is written per domain; omit for a host-only cookie. */
  domains?: string[]
  secure?: boolean
}

// Pure — kept separate from the `document.cookie` glue below so it is unit-testable without a DOM.
export function buildTrackingCookieStrings(
  value: string,
  options: TrackingCookieOptions = {},
  expires?: string,
): string[] {
  const domains: (string | undefined)[] =
    options.domains && options.domains.length > 0 ? options.domains : [undefined]
  return domains.map((domain) => {
    const parts = [`${COOKIE_NAME}=${value}`, 'path=/']
    if (expires) parts.push(`expires=${expires}`)
    if (domain) parts.push(`domain=${domain}`)
    if (options.secure) parts.push('secure')
    return parts.join(';')
  })
}

export function setTrackingToken(authId: string, options: TrackingCookieOptions = {}): void {
  for (const cookie of buildTrackingCookieStrings(authId, options)) {
    document.cookie = cookie
  }
}

export function getTrackingToken(): string | undefined {
  return document.cookie
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE_NAME}=`))
    ?.slice(COOKIE_NAME.length + 1)
}

export function clearTrackingToken(options: TrackingCookieOptions = {}): void {
  const expired = new Date(0).toUTCString()
  for (const cookie of buildTrackingCookieStrings('', options, expired)) {
    document.cookie = cookie
  }
}
