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

import type { AmZeroPageLogin } from './types.ts'

// Port of legacy RESTLoginView.isZeroPageLoginAllowed (org/forgerock/openam/ui/user/login/RESTLoginView.js,
// ~191-204): disabled -> never; no referrer -> allowedWithoutReferer; otherwise an empty/missing whitelist
// allows any referrer, else the referrer must exact-string match an entry.
export function isZeroPageLoginAllowed(config: AmZeroPageLogin, referrer: string): boolean {
  if (!config.enabled) {
    return false
  }
  if (!referrer) {
    return config.allowedWithoutReferer
  }
  return !config.refererWhitelist || config.refererWhitelist.length === 0 ||
    config.refererWhitelist.includes(referrer)
}
