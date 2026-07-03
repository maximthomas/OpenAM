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

// Only the pure cookie-string builder is tested here — this package's vitest environment is
// 'node' (no DOM), so get/set/clear (which touch document.cookie) are exercised indirectly via
// openam-ui-eui's jsdom-based useLogin/LoginPage tests instead.

import { describe, expect, it } from 'vitest'
import { buildTrackingCookieStrings } from './trackingToken.ts'

describe('buildTrackingCookieStrings', () => {
  it('builds a single host-only cookie when no domains are given', () => {
    const cookies = buildTrackingCookieStrings('abc123')
    expect(cookies).toEqual(['authId=abc123;path=/'])
  })

  it('builds one cookie per domain', () => {
    const cookies = buildTrackingCookieStrings('abc123', { domains: ['.example.com', '.example.org'] })
    expect(cookies).toEqual(['authId=abc123;path=/;domain=.example.com', 'authId=abc123;path=/;domain=.example.org'])
  })

  it('appends secure when requested', () => {
    const cookies = buildTrackingCookieStrings('abc123', { secure: true })
    expect(cookies).toEqual(['authId=abc123;path=/;secure'])
  })

  it('appends an expires attribute for clearing', () => {
    const cookies = buildTrackingCookieStrings('', {}, 'Thu, 01 Jan 1970 00:00:00 GMT')
    expect(cookies).toEqual(['authId=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT'])
  })
})
