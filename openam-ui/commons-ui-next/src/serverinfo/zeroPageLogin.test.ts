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
import { isZeroPageLoginAllowed } from './zeroPageLogin.ts'
import type { AmZeroPageLogin } from './types.ts'

describe('isZeroPageLoginAllowed', () => {
  it('is false when disabled, regardless of referrer or whitelist', () => {
    const config: AmZeroPageLogin = {
      enabled: false,
      refererWhitelist: ['https://trusted.example.com'],
      allowedWithoutReferer: true,
    }
    expect(isZeroPageLoginAllowed(config, '')).toBe(false)
    expect(isZeroPageLoginAllowed(config, 'https://trusted.example.com')).toBe(false)
  })

  it('with no referrer, defers to allowedWithoutReferer', () => {
    expect(
      isZeroPageLoginAllowed({ enabled: true, refererWhitelist: [], allowedWithoutReferer: true }, ''),
    ).toBe(true)
    expect(
      isZeroPageLoginAllowed({ enabled: true, refererWhitelist: [], allowedWithoutReferer: false }, ''),
    ).toBe(false)
  })

  it('with a referrer and an empty whitelist, allows any referrer', () => {
    expect(
      isZeroPageLoginAllowed(
        { enabled: true, refererWhitelist: [], allowedWithoutReferer: false },
        'https://anything.example.com',
      ),
    ).toBe(true)
  })

  it('with a referrer and a whitelist, requires an exact match', () => {
    const config: AmZeroPageLogin = {
      enabled: true,
      refererWhitelist: ['https://trusted.example.com'],
      allowedWithoutReferer: false,
    }
    expect(isZeroPageLoginAllowed(config, 'https://trusted.example.com')).toBe(true)
    expect(isZeroPageLoginAllowed(config, 'https://untrusted.example.com')).toBe(false)
  })
})
