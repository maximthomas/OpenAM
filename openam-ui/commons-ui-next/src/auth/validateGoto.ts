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

import type { Transport } from '../transport.ts'

/**
 * Open-redirect guard: validate a `goto` URL via AM's server-side allowlist.
 * Returns the sanitized `successURL` if AM accepts it, or `null` if rejected (400) or on error.
 * Mirrors legacy `AuthNService.validateGotoUrl` / `RESTLoginHelper.setSuccessURL`.
 */
export async function validateGoto(transport: Transport, goto: string): Promise<string | null> {
  try {
    const decoded = decodeURIComponent(goto)
    const res = await transport('/users?_action=validateGoto', {
      method: 'POST',
      headers: {
        'Accept-API-Version': 'protocol=1.0,resource=2.0',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ goto: decoded }),
    })
    if (!res.ok) return null
    const data = (await res.json()) as { successURL?: string }
    return data.successURL ?? null
  } catch {
    return null
  }
}
