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
 * Auth URL parameter parsing for the login page (P1-5d).
 * Mirrors legacy RESTLoginView.handleParams + RESTLoginHelper.filterUrlParams.
 */

export type LoginParams = {
  authIndexType?: string
  authIndexValue?: string
  goto?: string
  gotoOnFail?: string
  ForceAuth?: string
  locale?: string
  arg?: string
}

// Legacy shorthand param → authIndexType value mapping.
// "authlevel" maps to "level"; others map to themselves.
const SHORTHAND_TO_INDEX_TYPE: Record<string, string> = {
  authlevel: 'level',
  module: 'module',
  service: 'service',
  user: 'user',
  resource: 'resource',
}

const PARAM_WHITELIST = new Set([
  'authIndexType',
  'authIndexValue',
  'goto',
  'gotoOnFail',
  'ForceAuth',
  'locale',
  'arg',
])

/**
 * Parse auth URL params from react-router's URLSearchParams (HashRouter exposes these as
 * the query portion of the hash fragment: `#/login?authIndexType=...`).
 *
 * Shorthand params (authlevel/module/service/user/resource) are mapped to
 * authIndexType/authIndexValue, matching legacy handleParams behavior.
 * Mapping is skipped when authIndexType is already set to "composite_advice".
 */
export function parseLoginParams(searchParams: URLSearchParams): LoginParams {
  const raw: Record<string, string> = {}
  searchParams.forEach((v, k) => {
    raw[k] = v
  })

  // Shorthand → authIndexType/authIndexValue (skip if composite_advice already set).
  if (raw['authIndexType'] !== 'composite_advice') {
    for (const [shorthand, indexType] of Object.entries(SHORTHAND_TO_INDEX_TYPE)) {
      if (raw[shorthand]) {
        raw['authIndexType'] = indexType
        raw['authIndexValue'] = raw[shorthand]
        break // only the first shorthand match wins
      }
    }
  }

  const result: LoginParams = {}
  for (const key of PARAM_WHITELIST) {
    if (raw[key] !== undefined) {
      ;(result as Record<string, string>)[key] = raw[key]
    }
  }
  return result
}

/**
 * Build the query string to append to `/authenticate` based on the parsed login params.
 * Only auth-selection params (authIndexType, authIndexValue, ForceAuth, locale, arg) are sent.
 */
export function buildAuthQuery(params: LoginParams): string {
  const AUTH_KEYS: Array<keyof LoginParams> = ['authIndexType', 'authIndexValue', 'ForceAuth', 'locale', 'arg']
  const qs = new URLSearchParams()
  for (const key of AUTH_KEYS) {
    const val = params[key]
    if (val) qs.set(key, val)
  }
  const str = qs.toString()
  return str ? `?${str}` : ''
}
