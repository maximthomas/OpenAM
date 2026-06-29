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
import { createI18nInstance } from './index.ts'

describe('createI18nInstance', () => {
  it('returns an initialized i18next instance', () => {
    const i18n = createI18nInstance()
    expect(i18n.isInitialized).toBe(true)
  })

  it('resolves login locale keys', () => {
    const i18n = createI18nInstance()
    expect(i18n.t('common.user.login')).toBe('Log in')
    expect(i18n.t('templates.user.LoginTemplate.forgotUsername')).toBe('Forgot Username?')
    expect(i18n.t('openam.authentication.unavailable')).toBe('Unable to login to OpenAM')
  })
})
