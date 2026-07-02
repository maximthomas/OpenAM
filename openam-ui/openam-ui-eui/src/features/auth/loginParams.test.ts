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

import { describe, expect, it } from 'vitest'
import { buildAuthQuery, extractIDTokens, parseLoginParams } from './loginParams.ts'

function sp(query: string): URLSearchParams {
  return new URLSearchParams(query)
}

describe('parseLoginParams', () => {
  it('passes authIndexType/authIndexValue through unchanged', () => {
    const result = parseLoginParams(sp('authIndexType=module&authIndexValue=DataStore'))
    expect(result).toEqual({ authIndexType: 'module', authIndexValue: 'DataStore' })
  })

  it('maps shorthand "module" to authIndexType=module + authIndexValue', () => {
    const result = parseLoginParams(sp('module=DataStore'))
    expect(result).toEqual({ authIndexType: 'module', authIndexValue: 'DataStore' })
  })

  it('maps shorthand "service" to authIndexType=service + authIndexValue', () => {
    const result = parseLoginParams(sp('service=ldapService'))
    expect(result).toEqual({ authIndexType: 'service', authIndexValue: 'ldapService' })
  })

  it('maps shorthand "authlevel" to authIndexType=level', () => {
    const result = parseLoginParams(sp('authlevel=2'))
    expect(result).toEqual({ authIndexType: 'level', authIndexValue: '2' })
  })

  it('maps shorthand "user" to authIndexType=user', () => {
    const result = parseLoginParams(sp('user=bjensen'))
    expect(result).toEqual({ authIndexType: 'user', authIndexValue: 'bjensen' })
  })

  it('maps shorthand "resource" to authIndexType=resource', () => {
    const result = parseLoginParams(sp('resource=https://app.example.com/api'))
    expect(result).toEqual({ authIndexType: 'resource', authIndexValue: 'https://app.example.com/api' })
  })

  it('skips shorthand mapping when composite_advice is set', () => {
    const result = parseLoginParams(sp('authIndexType=composite_advice&authIndexValue=advice&module=DataStore'))
    expect(result).toEqual({ authIndexType: 'composite_advice', authIndexValue: 'advice' })
  })

  it('only takes the first shorthand match', () => {
    const result = parseLoginParams(sp('module=DataStore&service=ldapService'))
    // URLSearchParams iteration order is insertion order
    expect(result.authIndexType).toBe('module')
    expect(result.authIndexValue).toBe('DataStore')
  })

  it('preserves goto, gotoOnFail, ForceAuth, locale, arg', () => {
    const result = parseLoginParams(
      sp('goto=http%3A%2F%2Fexample.com&gotoOnFail=%2Ffail&ForceAuth=true&locale=fr&arg=newsession'),
    )
    expect(result).toEqual({
      goto: 'http://example.com',
      gotoOnFail: '/fail',
      ForceAuth: 'true',
      locale: 'fr',
      arg: 'newsession',
    })
  })

  it('strips params not in the whitelist', () => {
    const result = parseLoginParams(sp('realm=/sub&unknownParam=x&goto=/dashboard'))
    // unknownParam is stripped; realm is whitelisted (P1-5e)
    expect(result).toEqual({ goto: '/dashboard', realm: '/sub' })
  })

  it('returns empty object for empty params', () => {
    expect(parseLoginParams(sp(''))).toEqual({})
  })
})

describe('buildAuthQuery', () => {
  it('builds query string from authIndexType and authIndexValue', () => {
    const q = buildAuthQuery({ authIndexType: 'module', authIndexValue: 'DataStore' })
    const parsed = new URLSearchParams(q.slice(1))
    expect(parsed.get('authIndexType')).toBe('module')
    expect(parsed.get('authIndexValue')).toBe('DataStore')
  })

  it('returns empty string when no auth-selection params', () => {
    expect(buildAuthQuery({ goto: '/dashboard' })).toBe('')
  })

  it('includes ForceAuth, locale, arg', () => {
    const q = buildAuthQuery({ ForceAuth: 'true', locale: 'de', arg: 'newsession' })
    const parsed = new URLSearchParams(q.slice(1))
    expect(parsed.get('ForceAuth')).toBe('true')
    expect(parsed.get('locale')).toBe('de')
    expect(parsed.get('arg')).toBe('newsession')
  })

  it('does not include goto, gotoOnFail, or realm', () => {
    const q = buildAuthQuery({ goto: '/home', gotoOnFail: '/fail', realm: '/sub', authIndexType: 'module' })
    expect(q).not.toContain('goto')
    expect(q).not.toContain('realm')
    expect(q).toContain('authIndexType')
  })

  it('starts with ? when non-empty', () => {
    const q = buildAuthQuery({ authIndexType: 'service', authIndexValue: 'ldap' })
    expect(q.startsWith('?')).toBe(true)
  })
})

describe('extractIDTokens', () => {
  it('returns empty array when no IDToken params present', () => {
    expect(extractIDTokens(sp(''))).toEqual([])
  })

  it('extracts IDToken1 and IDToken2 in order', () => {
    expect(extractIDTokens(sp('IDToken1=demo&IDToken2=changeit'))).toEqual(['demo', 'changeit'])
  })

  it('stops at the first gap in the sequence', () => {
    expect(extractIDTokens(sp('IDToken1=a&IDToken3=c'))).toEqual(['a'])
  })

  it('extracts a single IDToken1', () => {
    expect(extractIDTokens(sp('IDToken1=demo&goto=/home'))).toEqual(['demo'])
  })
})
