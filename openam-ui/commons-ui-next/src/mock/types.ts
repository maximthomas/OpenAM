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

export type AmCallbackOutput = {
  name: string
  value: number | string | string[]
}

export type AmCallbackInput = {
  name: string
  value: number | string
}

// Extend this union as new callback types are introduced per slice.
export type AmCallback = {
  type: 'NameCallback' | 'PasswordCallback'
  output: AmCallbackOutput[]
  input: AmCallbackInput[]
}

export type AmAuthChallenge = {
  authId: string
  template: string
  stage: string
  header: string
  callbacks: AmCallback[]
}

export type AmAuthSuccess = {
  tokenId: string
  successUrl: string
  realm: string
}

export type AmAuthError = {
  code: number
  reason: string
  message: string
}

export type AmServerInfo = {
  domains: string[]
  protectedUserAttributes: string[]
  cookieName: string
  secureCookie: boolean
  forgotPassword: string
  selfRegistration: string
  lang: string
  successfulUserRegistrationDestination: string
  socialImplementations: string[]
  referralsEnabled: string
  zeroPageLoginAllowed: boolean
  realm: string
  xuiUserSessionValidationEnabled: boolean
  FQDN: string
  inplaceUpgrade: boolean
}

export type AmSessionInfo = {
  username: string
  universalId: string
  realm: string
  latestAccessTime: string
  maxSessionExpirationTime: string
  maxIdleExpirationTime: string
  properties: Record<string, string>
}

export type AmLogoutResult = {
  result: boolean
}
