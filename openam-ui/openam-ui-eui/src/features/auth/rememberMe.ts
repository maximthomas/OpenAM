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

// RESTLoginView.js formSubmit/prefillLoginData port (P1-5j): remembers the entered username across
// logins. Uses the legacy cookie name ("login") for cross-app (XUI/EUI) coexistence interop — same
// precedent as P1-5i's `authId` tracking cookie (trackingToken.ts in commons-ui-next).

const COOKIE_NAME = 'login'
const EXPIRY_DAYS = 20

export function getRememberedLogin(): string | undefined {
  return document.cookie
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE_NAME}=`))
    ?.slice(COOKIE_NAME.length + 1)
}

export function setRememberedLogin(username: string): void {
  const expires = new Date()
  expires.setDate(expires.getDate() + EXPIRY_DAYS)
  document.cookie = `${COOKIE_NAME}=${username};path=/;expires=${expires.toUTCString()}`
}

export function clearRememberedLogin(): void {
  document.cookie = `${COOKIE_NAME}=;path=/;expires=${new Date(0).toUTCString()}`
}
