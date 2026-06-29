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

import type { AmServerInfo } from '../types.ts'

export const SERVER_INFO: AmServerInfo = {
  domains: ['.example.com'],
  protectedUserAttributes: [],
  cookieName: 'iPlanetDirectoryPro',
  secureCookie: false,
  forgotPassword: 'false',
  selfRegistration: 'false',
  lang: 'en-US',
  successfulUserRegistrationDestination: 'default',
  socialImplementations: [],
  referralsEnabled: 'false',
  zeroPageLoginAllowed: false,
  realm: '/',
  xuiUserSessionValidationEnabled: true,
  FQDN: 'openam.example.com',
  inplaceUpgrade: false,
}
