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

// Minimal in-memory session token holder. AM sets iPlanetDirectoryPro as an HttpOnly cookie
// for cross-request persistence; we also keep it in memory so the new app can include
// tokenId in /json/sessions query params. Full cookie/HttpOnly parity is deferred to P1-5.

let _token: string | undefined

export function getToken(): string | undefined {
  return _token
}

export function setToken(token: string): void {
  _token = token
}

export function clearToken(): void {
  _token = undefined
}
