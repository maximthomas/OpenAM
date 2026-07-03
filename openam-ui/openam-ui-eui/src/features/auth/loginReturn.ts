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

/**
 * Param recall for the return-to-login views (P1-5f) — the `fullLoginURL` equivalent over
 * sessionStorage. Mirrors legacy RESTLoginHelper.filterUrlParams's whitelist (no `realm`).
 */

const STORAGE_KEY = 'eui.login.returnParams'

const RETURN_PARAM_KEYS = ['arg', 'authIndexType', 'authIndexValue', 'goto', 'gotoOnFail', 'ForceAuth', 'locale']

export function filterLoginParams(searchParams: URLSearchParams): URLSearchParams {
  const filtered = new URLSearchParams()
  for (const key of RETURN_PARAM_KEYS) {
    const value = searchParams.get(key)
    if (value !== null) filtered.set(key, value)
  }
  return filtered
}

/** Records the current login entry params so a later failure/expired/logout view can recall them. */
export function rememberLoginParams(searchParams: URLSearchParams): void {
  sessionStorage.setItem(STORAGE_KEY, filterLoginParams(searchParams).toString())
}

/** Recalls the last-remembered login params, or an empty set if none were stored. */
export function recallLoginParams(): URLSearchParams {
  return new URLSearchParams(sessionStorage.getItem(STORAGE_KEY) ?? '')
}
